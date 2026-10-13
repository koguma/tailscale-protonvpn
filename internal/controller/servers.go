package controller

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proton's own server API requires an authenticated session, so the catalog
// comes from gluetun's regularly refreshed public dump (MIT licensed), with a
// snapshot baked into the binary as a fallback.
const sourceURL = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json"

//go:embed snapshot/servers.json
var serverSnapshot []byte

// Server is one ProtonVPN WireGuard server (one entry IP).
type Server struct {
	ID         string `json:"id"` // entry IP; unique per physical server
	Name       string `json:"name"`
	Hostname   string `json:"hostname,omitempty"`
	Country    string `json:"country"`
	CC         string `json:"cc,omitempty"` // ISO code of the exit country
	City       string `json:"city,omitempty"`
	IP         string `json:"ip"`
	PubKey     string `json:"pubkey"`
	P2P        bool   `json:"p2p,omitempty"` // supports NAT-PMP port forwarding
	SecureCore bool   `json:"secureCore,omitempty"`
	Streaming  bool   `json:"streaming,omitempty"`
	Free       bool   `json:"free,omitempty"`
	Tor        bool   `json:"tor,omitempty"`
}

type rawCatalog struct {
	Timestamp int64 `json:"timestamp"`
	Servers   []struct {
		VPN         string   `json:"vpn"`
		Country     string   `json:"country"`
		City        string   `json:"city"`
		ServerName  string   `json:"server_name"`
		Hostname    string   `json:"hostname"`
		WGPubKey    string   `json:"wgpubkey"`
		PortForward bool     `json:"port_forward"`
		IPs         []string `json:"ips"`
		Stream      bool     `json:"stream"`
		SecureCore  bool     `json:"secure_core"`
		Free        bool     `json:"free"`
		Tor         bool     `json:"tor"`
	} `json:"servers"`
}

func parseCatalog(b []byte) ([]Server, time.Time, error) {
	var raw rawCatalog
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, time.Time{}, err
	}
	seen := map[string]bool{}
	var out []Server
	for _, r := range raw.Servers {
		if r.VPN != "wireguard" || r.WGPubKey == "" {
			continue
		}
		for _, ip := range r.IPs {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, Server{
				ID: ip, Name: r.ServerName, Hostname: r.Hostname, Country: r.Country,
				CC: countryCode(r.ServerName, r.SecureCore), City: r.City, IP: ip, PubKey: r.WGPubKey,
				P2P: r.PortForward, SecureCore: r.SecureCore, Streaming: r.Stream, Free: r.Free, Tor: r.Tor,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Country != out[j].Country {
			return out[i].Country < out[j].Country
		}
		return naturalLess(out[i].Name, out[j].Name)
	})
	return out, time.Unix(raw.Timestamp, 0), nil
}

// countryCode derives the exit country from Proton's naming scheme:
// "US-CA#12" -> US, Secure Core "CH-US#1" -> US, "UK#3" -> GB.
func countryCode(name string, secureCore bool) string {
	base, _, _ := strings.Cut(name, "#")
	parts := strings.Split(base, "-")
	cc := parts[0]
	if secureCore && len(parts) > 1 {
		cc = parts[1]
	}
	if cc == "UK" {
		cc = "GB"
	}
	return cc
}

func naturalLess(a, b string) bool {
	pa, na, _ := strings.Cut(a, "#")
	pb, nb, _ := strings.Cut(b, "#")
	if pa != pb {
		return pa < pb
	}
	ia, ea := strconv.Atoi(strings.TrimSuffix(na, "-TOR"))
	ib, eb := strconv.Atoi(strings.TrimSuffix(nb, "-TOR"))
	if ea == nil && eb == nil && ia != ib {
		return ia < ib
	}
	return a < b
}

type CatalogMeta struct {
	Count   int       `json:"count"`
	Updated time.Time `json:"updated"`
	Fetched time.Time `json:"fetched,omitempty"`
	Source  string    `json:"source"`
	Error   string    `json:"error,omitempty"`
}

type Catalog struct {
	mu        sync.RWMutex
	servers   []Server
	byID      map[string]int
	meta      CatalogMeta
	cachePath string
	refreshMu sync.Mutex
}

// NewCatalog loads the embedded serverSnapshot, or the cached download at cachePath if it
// is newer. Call Loop to keep it refreshed.
func NewCatalog(cachePath string) *Catalog {
	c := &Catalog{cachePath: cachePath}
	emb, embTS, err := parseCatalog(serverSnapshot)
	if err != nil {
		log.Printf("embedded catalog: %v", err)
	}
	c.set(emb, embTS, "embedded")
	if b, err := os.ReadFile(cachePath); err == nil {
		if s, ts, err := parseCatalog(b); err == nil && len(s) > 0 && ts.After(embTS) {
			c.set(s, ts, "cache")
		}
	}
	return c
}

func (c *Catalog) set(s []Server, ts time.Time, source string) {
	idx := make(map[string]int, len(s))
	for i, sv := range s {
		idx[sv.ID] = i
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.servers, c.byID = s, idx
	c.meta.Count, c.meta.Updated, c.meta.Source = len(s), ts, source
}

func (c *Catalog) All() []Server {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.servers
}

func (c *Catalog) Get(id string) (Server, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	i, ok := c.byID[id]
	if !ok {
		return Server{}, false
	}
	return c.servers[i], true
}

// FindByPubKey matches a server from a pasted config against the catalog.
func (c *Catalog) FindByPubKey(pub, ip string) (Server, bool) {
	if s, ok := c.Get(ip); ok && s.PubKey == pub {
		return s, true
	}
	return Server{}, false
}

func (c *Catalog) Meta() CatalogMeta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.meta
}

func (c *Catalog) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	err := c.refresh(ctx)
	c.mu.Lock()
	c.meta.Fetched = time.Now()
	c.meta.Error = ""
	if err != nil {
		c.meta.Error = err.Error()
	}
	c.mu.Unlock()
	return err
}

func (c *Catalog) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("catalog fetch: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	s, ts, err := parseCatalog(b)
	if err != nil {
		return fmt.Errorf("catalog parse: %w", err)
	}
	if len(s) < 50 {
		return errors.New("catalog fetch: suspiciously few servers, keeping current list")
	}
	c.set(s, ts, "online")
	return os.WriteFile(c.cachePath, b, 0o600)
}

func (c *Catalog) Loop(ctx context.Context) {
	for {
		if err := c.Refresh(ctx); err != nil {
			log.Printf("server catalog refresh: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(12 * time.Hour):
		}
	}
}

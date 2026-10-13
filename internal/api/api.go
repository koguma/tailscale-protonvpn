package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/koguma/tailscale-protonvpn/internal/controller"
	"github.com/koguma/tailscale-protonvpn/internal/vpn"
	"github.com/koguma/tailscale-protonvpn/internal/web"
)

type api struct {
	version string
	ctl     *controller.Controller
	cat     *controller.Catalog
	users   []string
}

// New returns the HTTP handler. users optionally restricts access to these
// Tailscale logins (lower-case).
func New(ctl *controller.Controller, cat *controller.Catalog, users []string, version string) http.Handler {
	a := &api{ctl: ctl, cat: cat, users: users, version: version}
	mux := http.NewServeMux()
	files := http.FileServerFS(web.FS)
	mux.Handle("GET /", files)
	cached := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		files.ServeHTTP(w, r)
	})
	mux.Handle("GET /flags/", cached)
	mux.Handle("GET /map.js", cached)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/servers", a.servers)
	mux.HandleFunc("POST /api/state", a.updateState)
	mux.HandleFunc("POST /api/key", a.setKey)
	mux.HandleFunc("DELETE /api/key", a.deleteKey)
	mux.HandleFunc("POST /api/ping", a.ping)
	mux.HandleFunc("POST /api/catalog/refresh", a.refreshCatalog)
	mux.HandleFunc("POST /api/exit/recheck", func(w http.ResponseWriter, r *http.Request) {
		a.ctl.RecheckExit()
		writeJSON(w, map[string]bool{"ok": true})
	})
	return a.guard(mux)
}

// guard enforces the optional user allowlist (tailscale serve sets the
// Tailscale-User-Login header) and blocks cross-site writes: a custom header
// can't be sent cross-origin without a CORS preflight, which we never answer.
func (a *api) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(a.users) > 0 && !slices.Contains(a.users, strings.ToLower(r.Header.Get("Tailscale-User-Login"))) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Tailscale-Protonvpn") != "1" {
			http.Error(w, "missing X-Tailscale-Protonvpn header", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

type keyView struct {
	Set       bool     `json:"set"`
	Addresses []string `json:"addresses,omitempty"`
	NATPMP    *bool    `json:"natpmp,omitempty"`
	Label     string   `json:"label,omitempty"`
}

func (a *api) status(w http.ResponseWriter, r *http.Request) {
	st := a.ctl.State()
	kv := keyView{}
	if st.Key != nil {
		kv = keyView{Set: true, Addresses: st.Key.Addresses, NATPMP: st.Key.NATPMP, Label: st.Key.Label}
	}
	host, _ := os.Hostname()
	writeJSON(w, map[string]any{
		"state": map[string]any{
			"enabled": st.Enabled, "killSwitch": st.KillSwitch, "dnsViaVPN": st.DNSViaVPN,
			"portForward": st.PortForward, "pfTarget": st.PFTarget, "pfTargetPort": st.PFTargetPort,
			"server": st.Server, "key": kv,
		},
		"status":  a.ctl.Status(),
		"catalog": a.cat.Meta(),
		"hostIP":  a.ctl.HostInfo(),
		"host":    host,
		"version": a.version,
		"user":    r.Header.Get("Tailscale-User-Name"),
		"login":   r.Header.Get("Tailscale-User-Login"),
		"now":     time.Now(),
	})
}

func (a *api) servers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.cat.All())
}

type stateReq struct {
	Enabled      *bool   `json:"enabled"`
	KillSwitch   *bool   `json:"killSwitch"`
	DNSViaVPN    *bool   `json:"dnsViaVPN"`
	PortForward  *bool   `json:"portForward"`
	PFTarget     *string `json:"pfTarget"`
	PFTargetPort *int    `json:"pfTargetPort"`
	ServerID     *string `json:"serverId"`
}

func (a *api) updateState(w http.ResponseWriter, r *http.Request) {
	var req stateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	var srv *controller.Server
	if req.ServerID != nil {
		s, ok := a.cat.Get(*req.ServerID)
		if !ok {
			// may be the custom server from the pasted config
			if cur := a.ctl.State().Server; cur != nil && cur.ID == *req.ServerID {
				s, ok = *cur, true
			}
		}
		if !ok {
			writeErr(w, 404, errors.New("unknown server"))
			return
		}
		srv = &s
	}
	err := a.ctl.Update(func(st *controller.State) error {
		if req.KillSwitch != nil {
			st.KillSwitch = *req.KillSwitch
		}
		if req.DNSViaVPN != nil {
			st.DNSViaVPN = *req.DNSViaVPN
		}
		if req.PortForward != nil {
			st.PortForward = *req.PortForward
		}
		if req.PFTarget != nil {
			t := strings.TrimSpace(*req.PFTarget)
			if t != "" {
				ip, err := netip.ParseAddr(t)
				if err != nil || !ip.Is4() {
					return errors.New("forward target must be an IPv4 address (e.g. a 100.x.y.z tailnet IP) or empty for this machine")
				}
				t = ip.String()
			}
			st.PFTarget = t
		}
		if req.PFTargetPort != nil {
			if *req.PFTargetPort < 0 || *req.PFTargetPort > 65535 {
				return errors.New("target port out of range")
			}
			st.PFTargetPort = *req.PFTargetPort
		}
		if srv != nil {
			st.Server = srv
		}
		if req.Enabled != nil {
			if *req.Enabled && st.Key == nil {
				return errors.New("add a WireGuard key first")
			}
			if *req.Enabled && st.Server == nil {
				return errors.New("pick a server first")
			}
			st.Enabled = *req.Enabled
		}
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	a.status(w, r)
}

func (a *api) setKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	key, peer, err := controller.ParseWGConfig(req.Config)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if peer != nil {
		if s, ok := a.cat.FindByPubKey(peer.PubKey, peer.IP); ok {
			peer = &s
		}
	}
	err = a.ctl.Update(func(st *controller.State) error {
		st.Key = key
		if st.Server == nil && peer != nil {
			st.Server = peer
		}
		return nil
	})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	a.status(w, r)
}

func (a *api) deleteKey(w http.ResponseWriter, r *http.Request) {
	a.ctl.Update(func(st *controller.State) error {
		st.Key, st.Enabled = nil, false
		return nil
	})
	a.status(w, r)
}

func (a *api) ping(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if len(req.IDs) > 200 {
		req.IDs = req.IDs[:200]
	}
	var ips []string
	for _, id := range req.IDs {
		if s, ok := a.cat.Get(id); ok {
			ips = append(ips, s.IP)
		}
	}
	rounds := 3
	if len(ips) > 80 {
		rounds = 2
	}
	res, err := vpn.Ping(ips, rounds, 1500*time.Millisecond)
	if err != nil {
		writeErr(w, 500, fmt.Errorf("ping: %w", err))
		return
	}
	writeJSON(w, res) // keyed by IP == server ID
}

func (a *api) refreshCatalog(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := a.cat.Refresh(ctx); err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, a.cat.Meta())
}

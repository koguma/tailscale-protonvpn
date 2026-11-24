package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Gateway is Proton's in-tunnel gateway (DNS and NAT-PMP).
const Gateway = "10.2.0.1"

// markControl tags a socket with FWMark so the "fwmark -> tunnel" rule sends
// it through the VPN even though host traffic normally uses the main table.
func markControl(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, FWMark)
	}); err != nil {
		return err
	}
	return serr
}

type ExitInfo struct {
	IP      string    `json:"ip"`
	City    string    `json:"city,omitempty"`
	Region  string    `json:"region,omitempty"`
	Country string    `json:"country,omitempty"`
	Org     string    `json:"org,omitempty"`
	Loc     string    `json:"loc,omitempty"` // "lat,lon"
	Checked time.Time `json:"checked"`
	Error   string    `json:"error,omitempty"`
}

// tunnelClient makes HTTP requests from inside the tunnel, resolving names via
// Proton's DNS, to see what the internet sees for exit-node clients.
var tunnelClient = func() *http.Client {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Control: markControl, Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(Gateway, "53"))
	}}
	d := &net.Dialer{Control: markControl, Timeout: 10 * time.Second, Resolver: res}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp4", addr)
			},
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   true,
		},
	}
}()

// CheckExit looks up the public IP seen through the tunnel.
func CheckExit(ctx context.Context) ExitInfo { return ipLookup(ctx, tunnelClient) }

// CheckHost looks up this machine's own public IP (what exit-node clients
// appear as when the VPN is off).
func CheckHost(ctx context.Context) ExitInfo { return ipLookup(ctx, http.DefaultClient) }

func ipLookup(ctx context.Context, client *http.Client) ExitInfo {
	info := ExitInfo{Checked: time.Now()}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return info
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		info.Error = err.Error()
	}
	return info
}

var pingMu sync.Mutex

const (
	pingRounds    = 2                      // ICMP attempts per server
	pingGap       = time.Millisecond       // between any two echoes
	pingSubnetGap = 30 * time.Millisecond  // between echoes to the same /24
	pingGrace     = 800 * time.Millisecond // wait for replies after the last echo
	tcpTimeout    = 1500 * time.Millisecond
	tcpParallel   = 32
)

// Ping measures the round-trip time from this host to each IP over the
// normal uplink (what the tunnel's outer packets will experience).
//
// Proton rate-limits ICMP hard per machine, and one machine often owns dozens
// of neighbouring entry IPs (Secure Core especially), so echoes are spread
// across /24s and paced within each. Servers that still don't answer, or never
// answer ICMP at all, are timed with a TCP connect to port 443 instead, if
// tcpOK allows it. (Secure Core servers relay port 443 to the exit country, so
// a handshake there measures the whole route, not the hop to the server.)
func Ping(ips []string, tcpOK func(ip string) bool) (map[string]float64, error) {
	pingMu.Lock()
	defer pingMu.Unlock()
	var v4, rest []string
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			v4 = append(v4, a.String())
		} else if err == nil && tcpOK(ip) {
			rest = append(rest, a.String())
		}
	}
	best, err := pingICMP(v4)
	if err != nil {
		return nil, err
	}
	for _, ip := range v4 {
		if _, ok := best[ip]; !ok && tcpOK(ip) {
			rest = append(rest, ip)
		}
	}
	for ip, ms := range pingTCP(rest) {
		best[ip] = ms
	}
	return best, nil
}

// interleave orders IPs round-robin across their /24s so consecutive echoes
// go to different machines.
func interleave(ips []string) []string {
	var keys []string
	bySubnet := map[string][]string{}
	for _, ip := range ips {
		k := ip[:strings.LastIndexByte(ip, '.')]
		if _, ok := bySubnet[k]; !ok {
			keys = append(keys, k)
		}
		bySubnet[k] = append(bySubnet[k], ip)
	}
	out := make([]string, 0, len(ips))
	for len(out) < len(ips) {
		for _, k := range keys {
			if l := bySubnet[k]; len(l) > 0 {
				out = append(out, l[0])
				bySubnet[k] = l[1:]
			}
		}
	}
	return out
}

func pingICMP(ips []string) (map[string]float64, error) {
	best := map[string]float64{}
	if len(ips) == 0 {
		return best, nil
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	type echo struct {
		ip string
		at time.Time
	}
	id := rand.IntN(0xffff)
	var mu sync.Mutex
	sent := map[int]echo{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			now := time.Now()
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			e, ok := m.Body.(*icmp.Echo)
			if !ok || e.ID != id {
				continue
			}
			mu.Lock()
			if s, ok := sent[e.Seq]; ok && peer.String() == s.ip {
				ms := float64(now.Sub(s.at).Microseconds()) / 1000
				if cur, ok := best[s.ip]; !ok || ms < cur {
					best[s.ip] = ms
				}
			}
			mu.Unlock()
		}
	}()

	order := interleave(ips)
	last := map[string]time.Time{}
	next := time.Now()
	seq := 0
	for r := 0; r < pingRounds; r++ {
		for _, ip := range order {
			mu.Lock()
			_, answered := best[ip]
			mu.Unlock()
			if answered {
				continue // later rounds are retries for the silent ones
			}
			k := ip[:strings.LastIndexByte(ip, '.')]
			if t := last[k].Add(pingSubnetGap); t.After(next) {
				next = t
			}
			time.Sleep(time.Until(next))
			seq = (seq + 1) & 0xffff
			b, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("tailscale-protonvpn")}}).Marshal(nil)
			mu.Lock()
			sent[seq] = echo{ip, time.Now()}
			mu.Unlock()
			conn.WriteTo(b, &net.IPAddr{IP: net.ParseIP(ip)})
			last[k] = time.Now()
			next = last[k].Add(pingGap)
		}
	}
	time.Sleep(pingGrace)
	conn.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return best, nil
}

// pingTCP times a TCP handshake to port 443. A refusal is a reply too.
func pingTCP(ips []string) map[string]float64 {
	var mu sync.Mutex
	res := map[string]float64{}
	sem := make(chan struct{}, tcpParallel)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			d := net.Dialer{Timeout: tcpTimeout}
			start := time.Now()
			c, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
			rtt := time.Since(start)
			if err == nil {
				c.Close()
			} else if !errors.Is(err, syscall.ECONNREFUSED) {
				return
			}
			mu.Lock()
			res[ip] = float64(rtt.Microseconds()) / 1000
			mu.Unlock()
		}()
	}
	wg.Wait()
	return res
}

// dialTunnel opens a connection that is routed through the tunnel.
func dialTunnel(network, addr string) (net.Conn, error) {
	d := net.Dialer{Control: markControl, Timeout: 5 * time.Second}
	return d.Dial(network, addr)
}

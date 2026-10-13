package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
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

// Ping measures ICMP round-trip time from this host to each IP (over the
// normal uplink, i.e. what the tunnel's outer packets will experience).
func Ping(ips []string, rounds int, wait time.Duration) (map[string]float64, error) {
	pingMu.Lock()
	defer pingMu.Unlock()
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	id := rand.IntN(0xffff)
	var mu sync.Mutex
	sent := map[int]struct {
		ip string
		at time.Time
	}{}
	best := map[string]float64{}

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
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || echo.ID != id {
				continue
			}
			mu.Lock()
			s, ok := sent[echo.Seq]
			if ok && peer.String() == s.ip {
				ms := float64(now.Sub(s.at).Microseconds()) / 1000
				if cur, ok := best[s.ip]; !ok || ms < cur {
					best[s.ip] = ms
				}
			}
			mu.Unlock()
		}
	}()

	seq := 0
	for r := 0; r < rounds; r++ {
		for _, ip := range ips {
			dst, err := net.ResolveIPAddr("ip4", ip)
			if err != nil {
				continue
			}
			seq++
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("tailscale-protonvpn")}}
			b, _ := msg.Marshal(nil)
			mu.Lock()
			sent[seq] = struct {
				ip string
				at time.Time
			}{ip, time.Now()}
			mu.Unlock()
			conn.WriteTo(b, dst)
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(wait / time.Duration(rounds))
	}
	time.Sleep(wait / 2)
	conn.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return best, nil
}

// dialTunnel opens a connection that is routed through the tunnel.
func dialTunnel(network, addr string) (net.Conn, error) {
	d := net.Dialer{Control: markControl, Timeout: 5 * time.Second}
	return d.Dial(network, addr)
}

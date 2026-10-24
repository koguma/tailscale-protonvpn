package controller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/koguma/tailscale-protonvpn/internal/vpn"
)

// ForwardedPortFile holds the current public port, for scripts.
const ForwardedPortFile = "/run/tailscale-protonvpn/forwarded_port"

const (
	handshakeFresh = 3 * time.Minute // WireGuard rekeys every 2 min with keepalive on
	connectGrace   = 20 * time.Second
	pfInterval     = 45 * time.Second
	pfLifetime     = 60
)

type Status struct {
	Phase      string        `json:"phase"` // off | connecting | connected | stalled | error
	Message    string        `json:"message,omitempty"`
	Handshake  time.Time     `json:"handshake,omitempty"`
	RX         int64         `json:"rx"`
	TX         int64         `json:"tx"`
	Since      time.Time     `json:"since,omitempty"` // when the current server was selected
	Exit       *vpn.ExitInfo `json:"exit,omitempty"`
	PFPort     int           `json:"pfPort,omitempty"`
	PFInternal int           `json:"pfInternal,omitempty"` // port packets actually arrive on
	PFError    string        `json:"pfError,omitempty"`
	PFRenewed  time.Time     `json:"pfRenewed,omitempty"`
	NetError   string        `json:"netError,omitempty"`
	Leak       string        `json:"leak,omitempty"` // human description of what exit traffic does right now
}

type Controller struct {
	mu     sync.Mutex
	st     State
	status Status
	store  *Store
	cat    *Catalog

	recMu    sync.Mutex // serializes reconcile
	wg       *wgctrl.Client
	net      vpn.Router
	tornDown bool
	pfFails  int

	host *vpn.ExitInfo // this machine's own public IP/location

	// reconcileFn replaces reconcile (see WithoutNetwork).
	reconcileFn func()

	kick   chan struct{}
	kickPF chan struct{}
	kickIP chan struct{}
}

// Option customizes a Controller.
type Option func(*Controller)

// WithoutNetwork makes the controller only keep and persist state, never
// touching interfaces, routes or firewall rules. Used by tests.
func WithoutNetwork() Option {
	return func(c *Controller) { c.reconcileFn = func() {} }
}

// New creates a controller for the given saved state. Call Reconcile once,
// then Run.
func New(store *Store, st State, cat *Catalog, opts ...Option) (*Controller, error) {
	c := &Controller{
		st: st, store: store, cat: cat,
		kick: make(chan struct{}, 1), kickPF: make(chan struct{}, 1), kickIP: make(chan struct{}, 1),
	}
	c.status.Since = time.Now()
	for _, o := range opts {
		o(c)
	}
	if c.reconcileFn == nil {
		wg, err := wgctrl.New()
		if err != nil {
			return nil, fmt.Errorf("wireguard control: %w", err)
		}
		c.wg = wg
	}
	return c, nil
}

// Reconcile converges the system once (it also runs periodically via Run).
func (c *Controller) Reconcile() {
	if c.reconcileFn != nil {
		c.reconcileFn()
		return
	}
	c.reconcile()
}

func poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Update applies fn to the state, persists it and reconciles immediately.
func (c *Controller) Update(fn func(*State) error) error {
	c.mu.Lock()
	next := c.st
	if err := fn(&next); err != nil {
		c.mu.Unlock()
		return err
	}
	if err := c.store.Save(next); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("save state: %w", err)
	}
	c.st = next
	c.mu.Unlock()
	c.Reconcile()
	poke(c.kickPF)
	return nil
}

func (c *Controller) Run(ctx context.Context) {
	go c.pfLoop(ctx)
	go c.exitIPLoop(ctx)
	go c.hostIPLoop(ctx)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.kick:
		}
		c.reconcile()
	}
}

func (c *Controller) reconcile() {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	st := c.State()

	if !st.Enabled || st.Server == nil || st.Key == nil {
		if !c.tornDown {
			c.net.Teardown()
			vpn.DeleteTunnel()
			os.Remove(ForwardedPortFile)
			c.tornDown = true
			log.Printf("vpn off: exit-node traffic goes out directly")
		}
		msg := ""
		switch {
		case st.Key == nil:
			msg = "Add a ProtonVPN WireGuard key to get started"
		case st.Server == nil:
			msg = "Pick a server to connect"
		}
		c.mu.Lock()
		c.status = Status{Phase: "off", Message: msg, Leak: "direct"}
		c.mu.Unlock()
		return
	}
	c.tornDown = false

	changed, tunErr := vpn.EnsureTunnel(c.wg, vpn.TunnelConfig{
		PrivateKey: st.Key.PrivateKey, Addresses: st.Key.Addresses,
		PeerKey: st.Server.PubKey, PeerIP: st.Server.IP,
	})
	stats, _ := vpn.ReadStats(c.wg)

	c.mu.Lock()
	if changed {
		log.Printf("tunnel: peer set to %s (%s)", st.Server.Name, st.Server.IP)
		c.status.Since = time.Now()
		c.status.Exit = nil
		c.status.PFPort, c.status.PFInternal = 0, 0
		c.status.PFError = ""
		os.Remove(ForwardedPortFile)
	}
	since := c.status.Since
	pfPort, pfInternal := c.status.PFPort, c.status.PFInternal
	prevPhase := c.status.Phase
	c.mu.Unlock()

	phase, msg, healthy := tunnelPhase(tunErr, stats.Handshake, since, time.Now())
	d := desiredNet(st, healthy, pfPort, pfInternal)
	netErr := c.net.Apply(d)
	if netErr != nil {
		log.Printf("network: %v", netErr)
	}

	leak := "vpn"
	switch {
	case !healthy && st.KillSwitch:
		leak = "blocked"
	case !healthy:
		leak = "direct"
	}

	c.mu.Lock()
	c.status.Phase, c.status.Message = phase, msg
	c.status.Handshake, c.status.RX, c.status.TX = stats.Handshake, stats.RX, stats.TX
	c.status.Leak = leak
	c.status.NetError = ""
	if netErr != nil {
		c.status.NetError = netErr.Error()
	}
	c.mu.Unlock()

	if phase != prevPhase {
		log.Printf("tunnel: %s %s", phase, msg)
		if phase == "connected" {
			poke(c.kickPF)
			poke(c.kickIP)
		}
	}
}

func (c *Controller) setPF(port, internal int, errMsg string) {
	c.mu.Lock()
	prev, prevIn := c.status.PFPort, c.status.PFInternal
	c.status.PFPort, c.status.PFInternal, c.status.PFError = port, internal, errMsg
	if port > 0 && errMsg == "" {
		c.status.PFRenewed = time.Now()
	}
	c.mu.Unlock()
	if port != prev || internal != prevIn {
		f := ForwardedPortFile
		if port > 0 {
			log.Printf("port forwarding: public port %d", port)
			os.WriteFile(f, []byte(strconv.Itoa(port)+"\n"), 0o644)
		} else {
			os.Remove(f)
		}
		poke(c.kick)
	}
}

func (c *Controller) pfLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(pfInterval):
		case <-c.kickPF:
		}
		st, status := c.State(), c.Status()
		switch {
		case !st.Enabled || !st.PortForward || st.Server == nil || st.Key == nil:
			c.pfFails = 0
			c.setPF(0, 0, "")
			continue
		case !st.Server.P2P && st.Server.Country != "Custom":
			c.setPF(0, 0, "This server doesn't support port forwarding. Pick a P2P server.")
			continue
		case st.Key.NATPMP != nil && !*st.Key.NATPMP:
			c.setPF(0, 0, "Your key was generated without NAT-PMP. Create a new WireGuard config with \"NAT-PMP (Port Forwarding)\" enabled.")
			continue
		case status.Phase != "connected":
			continue
		}
		udp, _, err1 := vpn.RequestPort(vpn.ProtoUDP, pfLifetime)
		tcp, tcpIn, err2 := vpn.RequestPort(vpn.ProtoTCP, pfLifetime)
		if err := errors.Join(err1, err2); err != nil {
			c.pfFails++
			log.Printf("port forwarding: %v", err)
			keep := status.PFPort
			if c.pfFails >= 3 {
				keep = 0
			}
			c.setPF(keep, status.PFInternal, err.Error())
			continue
		}
		c.pfFails = 0
		if udp != tcp {
			log.Printf("port forwarding: udp port %d != tcp port %d, using tcp", udp, tcp)
		}
		c.setPF(tcp, tcpIn, "")
	}
}

func (c *Controller) exitIPLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		case <-c.kickIP:
			time.Sleep(time.Second)
		}
		if c.Status().Phase != "connected" {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		info := vpn.CheckExit(cctx)
		cancel()
		c.mu.Lock()
		if c.status.Phase == "connected" {
			c.status.Exit = &info
		}
		c.mu.Unlock()
	}
}

func (c *Controller) RecheckExit() { poke(c.kickIP) }

func (c *Controller) hostIPLoop(ctx context.Context) {
	for {
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		info := vpn.CheckHost(cctx)
		cancel()
		wait := 6 * time.Hour
		if info.Error != "" {
			wait = 5 * time.Minute
		}
		c.mu.Lock()
		if info.Error == "" || c.host == nil {
			c.host = &info
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *Controller) HostInfo() *vpn.ExitInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.host
}

// tunnelPhase classifies the tunnel from its last WireGuard handshake.
func tunnelPhase(tunErr error, handshake, since, now time.Time) (phase, msg string, healthy bool) {
	healthy = tunErr == nil && !handshake.IsZero() && now.Sub(handshake) < handshakeFresh
	switch {
	case tunErr != nil:
		return "error", tunErr.Error(), false
	case healthy:
		return "connected", "", true
	case now.Sub(since) < connectGrace:
		return "connecting", "", false
	default:
		return "stalled", "No handshake from the server. The key may be expired/revoked, or the server is down - try another server.", false
	}
}

// desiredNet derives routing and firewall state from the settings and tunnel
// health. This is where the kill switch semantics live.
func desiredNet(st State, healthy bool, pfPort, pfInternal int) vpn.Desired {
	v6 := st.Key.HasV6()
	d := vpn.Desired{
		Exit4:    healthy || st.KillSwitch,
		Block4:   st.KillSwitch,
		Exit6:    v6 && (healthy || st.KillSwitch),
		Block6:   !v6 || st.KillSwitch, // without tunnel IPv6, v6 would bypass the VPN
		TunnelV6: v6,
	}
	for _, a := range st.Key.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			d.TunnelAddrs = append(d.TunnelAddrs, p.Addr())
		}
	}
	// Exit clients' DNS follows their traffic: tunnel when up, blocked by
	// the kill switch when down, direct when the kill switch is off.
	d.DNS = st.DNSViaVPN && healthy
	d.DNSBlock = st.DNSViaVPN && !healthy && st.KillSwitch
	if healthy && st.PortForward && pfPort > 0 {
		d.PFPort, d.PFInternal, d.PFTarget, d.PFTargetPort = pfPort, pfInternal, st.PFTarget, st.PFTargetPort
	}
	return d
}

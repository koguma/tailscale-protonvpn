package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/koguma/tailscale-protonvpn/internal/api"
	"github.com/koguma/tailscale-protonvpn/internal/controller"
	"github.com/koguma/tailscale-protonvpn/internal/vpn"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// Paths and defaults.
const (
	defaultListen = "127.0.0.1:8787"
	stateDir      = "/var/lib/tailscale-protonvpn"
	installPath   = "/usr/local/bin/tailscale-protonvpn"
	unitPath      = "/etc/systemd/system/tailscale-protonvpn.service"
)

const unitTemplate = `[Unit]
Description=ProtonVPN routing for this Tailscale exit node (tailscale-protonvpn)
Documentation=https://github.com/koguma/tailscale-protonvpn
Wants=network-online.target
After=network-online.target
# Set up the kill switch before tailscaled starts accepting exit traffic.
Before=tailscaled.service

[Service]
Type=notify
ExecStart=%s serve --listen %s
Restart=always
RestartSec=3
TimeoutStartSec=30
StateDirectory=tailscale-protonvpn
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

func usage() {
	fmt.Fprint(os.Stderr, `tailscale-protonvpn - route a Tailscale exit node through ProtonVPN

Usage:
  tailscale-protonvpn serve     [--listen 127.0.0.1:8787] [--state-dir /var/lib/tailscale-protonvpn] [--allow-users a@x,b@y]
  tailscale-protonvpn install   [--listen 127.0.0.1:8787] [--https-port 443] [--no-serve] [--no-advertise]
  tailscale-protonvpn uninstall [--purge]
  tailscale-protonvpn up        start the service (undo down) and wait for the VPN to connect
  tailscale-protonvpn down      stop the service and remove the tunnel, routing and firewall rules
                       (exit traffic goes direct until the service starts again)
  tailscale-protonvpn version
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0) // journald timestamps for us
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("tailscale-protonvpn", version)
	case "up":
		err = cmdUp()
	case "down":
		err = cmdDown()
	default:
		usage()
	}
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

// cmdServe runs the daemon: the reconcile loop plus the dashboard on --listen.
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", defaultListen, "dashboard listen address (keep it on loopback; expose it with tailscale serve)")
	dir := fs.String("state-dir", stateDir, "state directory")
	allow := fs.String("allow-users", "", "comma-separated Tailscale logins allowed to use the dashboard (default: anyone who can reach it)")
	fs.Parse(args)

	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(controller.ForwardedPortFile), 0o755)

	store := controller.NewStore(filepath.Join(*dir, "state.json"))
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	cat := controller.NewCatalog(filepath.Join(*dir, "servers.json"))
	ctl, err := controller.New(store, st, cat)
	if err != nil {
		return err
	}

	// Bring the network into the desired state before telling systemd we're
	// ready; the unit is ordered Before=tailscaled, so the kill switch is in
	// place before any exit-node traffic can arrive.
	ctl.Reconcile()
	sdNotify("READY=1")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go ctl.Run(ctx)
	go cat.Loop(ctx)

	var users []string
	for _, u := range strings.Split(*allow, ",") {
		if u = strings.TrimSpace(u); u != "" {
			users = append(users, strings.ToLower(u))
		}
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(ctl, cat, users, version),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Printf("tailscale-protonvpn %s: dashboard listening on http://%s", version, *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Deliberately leave the tunnel and routing in place: kernel WireGuard
	// keeps working without us, so restarts/upgrades don't drop or leak
	// exit-node traffic. `tailscale-protonvpn down` tears everything down.
	log.Printf("shutting down (tunnel left in place)")
	return nil
}

// sdNotify sends a readiness notification to systemd (Type=notify units).
func sdNotify(state string) {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return
	}
	if p[0] == '@' {
		p = "\x00" + p[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}

// cmdInstall sets up (or upgrades) the binary, systemd unit and tailscale serve.
func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	listen := fs.String("listen", defaultListen, "dashboard listen address")
	httpsPort := fs.Int("https-port", 443, "tailscale serve HTTPS port for the dashboard")
	noServe := fs.Bool("no-serve", false, "don't expose the dashboard with tailscale serve")
	noAdvertise := fs.Bool("no-advertise", false, "don't advertise this machine as a Tailscale exit node")
	fs.Parse(args)

	if err := preflight(); err != nil {
		return err
	}
	if err := enableForwarding(); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}
	upstream := "http://" + *listen
	if !*noServe {
		if err := checkServePort(*httpsPort, upstream); err != nil {
			return err
		}
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if self != installPath {
		if err := copyExecutable(self, installPath); err != nil {
			return fmt.Errorf("install binary: %w", err)
		}
		fmt.Println("✓ installed", installPath)
	}
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unitTemplate, installPath, *listen)), 0o644); err != nil {
		return err
	}
	for _, c := range [][]string{{"daemon-reload"}, {"enable", "tailscale-protonvpn.service"}, {"restart", "tailscale-protonvpn.service"}} {
		if _, err := vpn.Run("systemctl", c...); err != nil {
			return err
		}
	}
	fmt.Println("✓ tailscale-protonvpn.service enabled and started")

	if !*noAdvertise {
		if _, err := vpn.Run("tailscale", "set", "--advertise-exit-node"); err != nil {
			fmt.Println("! could not advertise exit node:", err)
		} else {
			fmt.Println("✓ advertising as exit node (approve it in the Tailscale admin console if it isn't auto-approved)")
		}
	}

	url := "https://<this-machine>.<tailnet>.ts.net"
	if out, err := vpn.Run("tailscale", "status", "--self", "--json"); err == nil {
		var s struct{ Self struct{ DNSName string } }
		if json.Unmarshal([]byte(out), &s) == nil && s.Self.DNSName != "" {
			url = "https://" + strings.TrimSuffix(s.Self.DNSName, ".")
		}
	}
	if *httpsPort != 443 {
		url += fmt.Sprintf(":%d", *httpsPort)
	}
	if *noServe {
		fmt.Printf("\nDashboard listens on %s (not exposed; try: ssh -L 8787:%s <host>)\n", upstream, *listen)
		return nil
	}
	// The serve config is stored by tailscaled, so it survives reboots.
	if _, err := vpn.Run("tailscale", "serve", "--bg", fmt.Sprintf("--https=%d", *httpsPort), upstream); err != nil {
		return fmt.Errorf("tailscale serve: %w\n  HTTPS certificates must be enabled for your tailnet (admin console → DNS → HTTPS Certificates),\n  or reinstall with --no-serve", err)
	}
	fmt.Printf("\nDashboard (tailnet only): %s\nOpen it, paste a ProtonVPN WireGuard config, and pick a server.\n", url)
	return nil
}

// preflight checks everything tailscale-protonvpn needs, with actionable errors.
func preflight() error {
	if runtime.GOOS != "linux" {
		return errors.New("tailscale-protonvpn only runs on Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root (try: sudo tailscale-protonvpn install)")
	}
	hints := map[string]string{
		"ip":                "install iproute2",
		"iptables-restore":  "install iptables (iptables-nft is fine)",
		"ip6tables-restore": "install iptables (iptables-nft is fine)",
		"tailscale":         "install Tailscale: https://tailscale.com/download/linux",
		"systemctl":         "tailscale-protonvpn needs systemd",
	}
	for _, bin := range []string{"systemctl", "tailscale", "ip", "iptables-restore", "ip6tables-restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%q not found: %s", bin, hints[bin])
		}
	}
	if out, err := vpn.Run("tailscale", "status", "--self", "--json"); err != nil {
		return fmt.Errorf("tailscale isn't running or logged in (run: tailscale up): %w", err)
	} else if strings.Contains(out, `"BackendState": "NeedsLogin"`) {
		return errors.New("tailscale needs login (run: tailscale up)")
	}
	if _, err := net.InterfaceByName("tailscale0"); err != nil {
		return errors.New("no tailscale0 interface: tailscaled must run with a TUN device, not --tun=userspace-networking")
	}
	// Kernel WireGuard (built in since Linux 5.6).
	if !vpn.TunnelExists() {
		const probe = "pe-wgprobe0"
		if _, err := vpn.Run("ip", "link", "add", probe, "type", "wireguard"); err != nil {
			return fmt.Errorf("kernel WireGuard unavailable (needs Linux 5.6+ or the wireguard module; containers like OpenVZ/LXC may not allow it): %w", err)
		}
		vpn.Run("ip", "link", "del", probe)
	}
	return nil
}

const sysctlPath = "/etc/sysctl.d/99-tailscale-protonvpn.conf"

// enableForwarding turns on IP forwarding, which any Tailscale exit node needs.
func enableForwarding() error {
	v4, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	v6, _ := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if strings.TrimSpace(string(v4)) == "1" && strings.TrimSpace(string(v6)) == "1" {
		return nil
	}
	conf := "# Added by tailscale-protonvpn: required for a Tailscale exit node.\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
	if err := os.WriteFile(sysctlPath, []byte(conf), 0o644); err != nil {
		return err
	}
	if _, err := vpn.Run("sysctl", "-p", sysctlPath); err != nil {
		return err
	}
	fmt.Println("✓ enabled IP forwarding (" + sysctlPath + ")")
	return nil
}

// checkServePort refuses to clobber an existing tailscale serve config.
func checkServePort(port int, upstream string) error {
	out, err := vpn.Run("tailscale", "serve", "status", "--json")
	if err != nil {
		return nil // older tailscale or nothing configured; serve will report problems itself
	}
	return serveConflict(out, port, upstream)
}

// serveConflict reports whether `tailscale serve status --json` output shows
// port already serving "/" from something other than upstream.
func serveConflict(statusJSON string, port int, upstream string) error {
	var st struct {
		Web map[string]struct {
			Handlers map[string]struct{ Proxy string }
		}
	}
	if json.Unmarshal([]byte(statusJSON), &st) != nil {
		return nil
	}
	suffix := fmt.Sprintf(":%d", port)
	for host, w := range st.Web {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		if h, ok := w.Handlers["/"]; ok && h.Proxy != upstream {
			return fmt.Errorf("tailscale serve already uses port %d for %s; pick another with --https-port 8443, or --no-serve", port, h.Proxy)
		}
	}
	return nil
}

// cmdUninstall reverses cmdInstall.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete saved state (WireGuard key, settings)")
	httpsPort := fs.Int("https-port", 443, "tailscale serve HTTPS port to turn off")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	vpn.Run("tailscale", "serve", fmt.Sprintf("--https=%d", *httpsPort), "off")
	vpn.Run("systemctl", "disable", "--now", "tailscale-protonvpn.service")
	os.Remove(unitPath)
	vpn.Run("systemctl", "daemon-reload")
	if err := teardownAll(); err != nil {
		return err
	}
	if *purge {
		os.RemoveAll(stateDir)
	}
	os.Remove(installPath)
	fmt.Println("tailscale-protonvpn uninstalled")
	return nil
}

// copyExecutable installs src at dst atomically.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tailscale-protonvpn-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst) // rename, so a running binary isn't "text file busy"
}

// cmdUp starts the service and reports once the tunnel is connected.
func cmdUp() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		return errors.New("tailscale-protonvpn isn't installed; run: tailscale-protonvpn install")
	}
	if _, err := vpn.Run("systemctl", "start", "tailscale-protonvpn.service"); err != nil {
		return err
	}
	fmt.Println("✓ started tailscale-protonvpn.service")

	listen := defaultListen
	if f := strings.Fields(string(unit)); len(f) > 0 {
		for i, w := range f {
			if w == "--listen" && i+1 < len(f) {
				listen = f[i+1]
			}
		}
	}
	type statusResp struct {
		State struct {
			Enabled bool
			Server  *controller.Server
		}
		Status controller.Status
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var last statusResp
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		resp, err := client.Get("http://" + listen + "/api/status")
		if err != nil {
			continue
		}
		var s statusResp
		err = json.NewDecoder(resp.Body).Decode(&s)
		resp.Body.Close()
		if err != nil {
			continue
		}
		last = s
		if !s.State.Enabled {
			fmt.Println("The VPN is switched off in the dashboard, so exit-node traffic goes direct. Turn it on there.")
			return nil
		}
		if s.Status.Phase == "connected" && s.Status.Exit != nil && s.Status.Exit.IP != "" {
			break
		}
	}
	st := last.Status
	switch {
	case st.Phase == "connected":
		where := ""
		if last.State.Server != nil {
			where = " via " + last.State.Server.Name
		}
		fmt.Printf("✓ connected%s", where)
		if st.Exit != nil && st.Exit.IP != "" {
			fmt.Printf(", exit IP %s (%s)", st.Exit.IP, strings.Trim(st.Exit.City+", "+st.Exit.Country, ", "))
		}
		fmt.Println()
		if st.PFPort > 0 {
			fmt.Printf("✓ forwarded port %d\n", st.PFPort)
		}
	case st.Phase == "":
		return errors.New("the service started but its dashboard isn't answering; check: journalctl -u tailscale-protonvpn")
	default:
		fmt.Printf("! not connected yet (%s) %s\n  check the dashboard or: journalctl -u tailscale-protonvpn\n", st.Phase, st.Message)
	}
	return nil
}

// cmdDown stops the service first; otherwise its reconcile loop would rebuild
// the tunnel within seconds.
func cmdDown() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if _, err := vpn.Run("systemctl", "is-active", "--quiet", "tailscale-protonvpn.service"); err == nil {
		if _, err := vpn.Run("systemctl", "stop", "tailscale-protonvpn.service"); err != nil {
			return err
		}
		fmt.Println("✓ stopped tailscale-protonvpn.service")
	}
	if err := teardownAll(); err != nil {
		return err
	}
	fmt.Println("\nExit-node traffic now leaves directly. Start again with: sudo tailscale-protonvpn up")
	if _, err := vpn.Run("systemctl", "is-enabled", "--quiet", "tailscale-protonvpn.service"); err == nil {
		fmt.Println("(it will also start on the next boot; to prevent that: systemctl disable tailscale-protonvpn)")
	}
	return nil
}

// teardownAll removes the tunnel, routing rules and firewall chains.
func teardownAll() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	var n vpn.Router
	n.Teardown()
	vpn.DeleteTunnel()
	os.Remove(controller.ForwardedPortFile)
	fmt.Println("✓ removed tunnel, routing rules and firewall chains")
	return nil
}

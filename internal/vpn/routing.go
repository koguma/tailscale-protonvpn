package vpn

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Table is the routing table holding the default route into the tunnel.
const Table = 51820

// FWMark marks host sockets that must use the tunnel (NAT-PMP, exit-IP probe).
const FWMark = 0xca6c

// tsBypassMark is the mark tailscaled puts on its own sockets (rule 5210).
const tsBypassMark = 0x80000

// tsCgroup is tailscaled's cgroup (v2, relative to /sys/fs/cgroup).
const tsCgroup = "system.slice/tailscaled.service"

// Rule priorities. Tailscale uses 5210-5270 (5270 = "lookup 52", the tailnet
// routes), so exit traffic is matched right after it: tailnet destinations
// still go to tailscale0, everything else from tailscale0 goes to the tunnel.
const (
	prefSport   = 5199 // udp from the forwarded port -> tunnel (see rules)
	prefMark    = 5200 // fwmark FWMark -> tunnel (host sockets that opt in)
	prefDNSBase = 5201 // retired "to <upstream DNS>" rules, still removed on upgrade
	prefDNSMax  = 5208
	prefSrc     = 5209 // from <tunnel address> -> tunnel (replies from local listeners)
	prefExit    = 5275 // iif tailscale0 -> tunnel
	prefBlock   = 5276 // iif tailscale0 -> prohibit (kill switch / v6 leak guard)
)

var managedPrefs = func() []int {
	p := []int{prefSport, prefMark, prefSrc, prefExit, prefBlock}
	for i := prefDNSBase; i <= prefDNSMax; i++ {
		p = append(p, i)
	}
	return p
}()

// Desired is the complete network state derived from State + tunnel health.
type Desired struct {
	Exit4, Exit6   bool // route exit-node traffic into the tunnel
	Block4, Block6 bool // prohibit exit-node traffic that the tunnel doesn't take
	TunnelV6       bool
	DNS            bool // send exit-node clients' DNS into the tunnel
	DNSBlock       bool // drop exit-node clients' DNS (kill switch, tunnel down)
	PFPort         int
	PFInternal     int // port Proton delivers to (normally == PFPort)
	TunnelAddrs    []netip.Addr
	PFTarget       string
	PFTargetPort   int
}

// Router applies Desired states to routing rules and firewall chains. The zero value is ready to use.
type Router struct {
	applied      map[string]string // "4/5275" -> rule args
	ipt          map[string]string // "iptables" -> restore payload
	iptAppliedAt time.Time
	cgIno        uint64 // inode of tsCgroup when the firewall was last applied
}

func ipFam(v6 bool) string {
	if v6 {
		return "-6"
	}
	return "-4"
}

func presentPrefs(v6 bool) map[int]bool {
	out, err := Run("ip", ipFam(v6), "rule", "show")
	m := map[int]bool{}
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		p, _, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			m[n] = true
		}
	}
	return m
}

func delPref(v6 bool, pref int) {
	for i := 0; i < 16; i++ {
		if _, err := Run("ip", ipFam(v6), "rule", "del", "pref", strconv.Itoa(pref)); err != nil {
			return
		}
	}
}

func (n *Router) rules(d Desired, v6 bool) map[int]string {
	r := map[int]string{
		prefMark: fmt.Sprintf("fwmark 0x%x lookup %d", FWMark, Table),
	}
	exit, block := d.Exit4, d.Block4
	if v6 {
		exit, block = d.Exit6, d.Block6
	}
	for _, a := range d.TunnelAddrs {
		if a.Is6() == v6 {
			r[prefSrc] = fmt.Sprintf("from %s lookup %d", a, Table)
		}
	}
	// A UDP listener bound to 0.0.0.0 (torrent clients, game servers) replies
	// without a source address, so the main table would send the reply out
	// the uplink from the host's real IP. Route by source port instead; the
	// kernel then picks the tunnel address and conntrack maps it back.
	if !v6 && d.PFPort > 0 && d.PFTarget == "" {
		port := d.PFTargetPort
		if port == 0 {
			port = d.PFPort
		}
		r[prefSport] = fmt.Sprintf("ipproto udp sport %d lookup %d", port, Table)
	}
	if exit {
		r[prefExit] = fmt.Sprintf("iif tailscale0 lookup %d", Table)
	}
	if block {
		r[prefBlock] = "iif tailscale0 prohibit"
	}
	return r
}

// Apply converges routes, rules and firewall chains onto d. It is cheap when
// nothing changed and self-heals if something (e.g. a tailscaled restart)
// removed our pieces.
func (n *Router) Apply(d Desired) error {
	if n.applied == nil {
		n.applied = map[string]string{}
		n.ipt = map[string]string{}
	}
	var errs []string
	if _, err := Run("ip", "-4", "route", "replace", "default", "dev", Interface, "table", strconv.Itoa(Table)); err != nil {
		errs = append(errs, err.Error())
	}
	if d.TunnelV6 {
		if _, err := Run("ip", "-6", "route", "replace", "default", "dev", Interface, "table", strconv.Itoa(Table)); err != nil {
			errs = append(errs, err.Error())
		}
	} else {
		Run("ip", "-6", "route", "flush", "table", strconv.Itoa(Table))
	}

	for _, v6 := range []bool{false, true} {
		want := n.rules(d, v6)
		present := presentPrefs(v6)
		// Add the block rule before touching the exit rule so that the kill
		// switch is never momentarily absent.
		prefs := append([]int(nil), managedPrefs...)
		sort.Slice(prefs, func(i, j int) bool { return prefs[i] == prefBlock || (prefs[j] != prefBlock && prefs[i] < prefs[j]) })
		for _, p := range prefs {
			k := fmt.Sprintf("%s/%d", ipFam(v6), p)
			w, ok := want[p]
			if !ok {
				if present[p] {
					delPref(v6, p)
				}
				delete(n.applied, k)
				continue
			}
			if present[p] && n.applied[k] == w {
				continue
			}
			delPref(v6, p)
			args := append([]string{ipFam(v6), "rule", "add", "pref", strconv.Itoa(p)}, strings.Fields(w)...)
			if _, err := Run("ip", args...); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			n.applied[k] = w
		}
	}

	if err := n.applyFirewall(d); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

type chainJump struct{ table, parent, chain string }

var jumps = []chainJump{
	{"filter", "INPUT", "PE-INPUT"},
	{"filter", "FORWARD", "PE-FORWARD"},
	{"nat", "PREROUTING", "PE-PRE"},
	{"nat", "POSTROUTING", "PE-POST"},
	{"mangle", "FORWARD", "PE-MSS"},
	{"mangle", "OUTPUT", "PE-DNS"},
}

// firewallPayload renders our chains. cgroup is tailscaled's cgroup path, or
// "" when it doesn't exist (a rule naming a missing cgroup fails to load).
func firewallPayload(d Desired, v6 bool, cgroup string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	pf := !v6 && d.PFPort > 0
	in := d.PFInternal
	if in == 0 {
		in = d.PFPort
	}
	tport := d.PFTargetPort
	if tport == 0 {
		tport = d.PFPort
	}

	w("*filter")
	w(":PE-INPUT - [0:0]")
	w(":PE-FORWARD - [0:0]")
	w("-A PE-INPUT -i %s -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT", Interface)
	if pf && d.PFTarget == "" && tport == in {
		for _, proto := range []string{"tcp", "udp"} {
			w("-A PE-INPUT -i %s -p %s -m %s --dport %d -j ACCEPT", Interface, proto, proto, in)
		}
	}
	w("-A PE-INPUT -i %s -j DROP", Interface)
	w("-A PE-FORWARD -i %s -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT", Interface)
	w("-A PE-FORWARD -i %s -j DROP", Interface)
	w("COMMIT")

	w("*nat")
	w(":PE-PRE - [0:0]")
	w(":PE-POST - [0:0]")
	if pf {
		for _, proto := range []string{"tcp", "udp"} {
			switch {
			case d.PFTarget != "":
				w("-A PE-PRE -i %s -p %s -m %s --dport %d -j DNAT --to-destination %s:%d", Interface, proto, proto, in, d.PFTarget, tport)
			case tport != in:
				w("-A PE-PRE -i %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d", Interface, proto, proto, in, tport)
			}
		}
		if d.PFTarget != "" {
			// SNAT to our tailnet IP so replies come back through us even if
			// the target device isn't using this exit node.
			w("-A PE-POST -o tailscale0 -d %s -m conntrack --ctstate DNAT -j MASQUERADE", d.PFTarget)
		}
	}
	if !v6 || d.TunnelV6 {
		w("-A PE-POST -o %s -j MASQUERADE", Interface)
	}
	w("COMMIT")

	w("*mangle")
	w(":PE-MSS - [0:0]")
	w("-A PE-MSS -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", Interface)
	w("-A PE-MSS -i %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", Interface)
	// Exit-node clients send DNS to tailscaled over the tailnet, and it
	// forwards them as plain DNS on port 53: over TCP from its marked
	// sockets, over UDP unmarked, so match both the mark and its cgroup. The
	// host's own lookups also pass through tailscaled under MagicDNS but go
	// out as DoH, so tailscaled + port 53 picks out only the exit clients'.
	w(":PE-DNS - [0:0]")
	target := ""
	switch {
	case d.DNSBlock, d.DNS && v6 && !d.TunnelV6:
		target = "DROP"
	case d.DNS:
		target = fmt.Sprintf("MARK --set-mark 0x%x", FWMark)
	}
	if target != "" {
		tailnet := "100.64.0.0/10"
		if v6 {
			tailnet = "fd7a:115c:a1e0::/48"
		}
		for _, proto := range []string{"udp", "tcp"} {
			w("-A PE-DNS ! -d %s -p %s -m %s --dport 53 -m mark --mark 0x%x/0xff0000 -j %s", tailnet, proto, proto, tsBypassMark, target)
			if cgroup != "" {
				w("-A PE-DNS ! -d %s -p %s -m %s --dport 53 -m cgroup --path %s -j %s", tailnet, proto, proto, cgroup, target)
			}
		}
	}
	w("COMMIT")
	return b.String()
}

func (n *Router) applyFirewall(d Desired) error {
	var errs []string
	refresh := time.Since(n.iptAppliedAt) > 5*time.Minute
	// The cgroup match binds to the cgroup that exists when the rule is
	// loaded, so reload whenever tailscaled restarts into a new one.
	cgroup, ino := "", uint64(0)
	if fi, err := os.Stat("/sys/fs/cgroup/" + tsCgroup); err == nil {
		cgroup = tsCgroup
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = st.Ino
		}
	}
	if ino != n.cgIno {
		refresh = true
	}
	for _, v6 := range []bool{false, true} {
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		payload := firewallPayload(d, v6, cgroup)
		if refresh || n.ipt[bin] != payload {
			if err := RunStdin(payload, bin+"-restore", "-w", "--noflush"); err != nil {
				errs = append(errs, err.Error())
				delete(n.ipt, bin)
				continue
			}
			n.ipt[bin] = payload
		}
		for _, j := range jumps {
			if _, err := Run(bin, "-w", "-t", j.table, "-C", j.parent, "-j", j.chain); err != nil {
				if _, err := Run(bin, "-w", "-t", j.table, "-I", j.parent, "1", "-j", j.chain); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
	}
	if refresh {
		n.iptAppliedAt = time.Now()
		n.cgIno = ino
	}
	if len(errs) > 0 {
		return fmt.Errorf("firewall: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Teardown removes every rule, route and chain we own.
func (n *Router) Teardown() {
	for _, v6 := range []bool{false, true} {
		present := presentPrefs(v6)
		for _, p := range managedPrefs {
			if present[p] {
				delPref(v6, p)
			}
		}
		Run("ip", ipFam(v6), "route", "flush", "table", strconv.Itoa(Table))
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		for _, j := range jumps {
			for i := 0; i < 8; i++ {
				if _, err := Run(bin, "-w", "-t", j.table, "-D", j.parent, "-j", j.chain); err != nil {
					break
				}
			}
			Run(bin, "-w", "-t", j.table, "-F", j.chain)
			Run(bin, "-w", "-t", j.table, "-X", j.chain)
		}
	}
	n.applied = nil
	n.ipt = nil
}

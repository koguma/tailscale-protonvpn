package vpn

import (
	"log"
	"net/netip"
	"os"
	"strings"
)

// UpstreamDNS returns the resolvers this host really uses (as opposed to
// tailscale's 100.100.100.100). Tailscale's exit-node DNS service resolves
// client queries through these, so routing them via the tunnel keeps exit
// clients' DNS inside the VPN too.
func UpstreamDNS() []netip.Addr {
	var out []netip.Addr
	if o, err := Run("resolvectl", "dns"); err == nil {
		out = parseResolvectl(o)
	}
	if len(out) == 0 {
		if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			out = parseResolvConf(string(b))
		}
	}
	if len(out) == 0 {
		log.Printf("dns: no upstream resolvers found")
	}
	return out
}

// resolverSet collects real upstream resolvers, skipping Tailscale's own
// (100.100.100.100 / fd7a:115c:a1e0::53), loopback stubs and duplicates.
type resolverSet struct {
	seen map[netip.Addr]bool
	out  []netip.Addr
}

func (r *resolverSet) add(tok string) {
	tok, _, _ = strings.Cut(tok, "#") // DoT server name
	tok, _, _ = strings.Cut(tok, "%") // interface scope
	a, err := netip.ParseAddr(tok)
	if err != nil {
		ap, err2 := netip.ParseAddrPort(tok)
		if err2 != nil {
			return
		}
		a = ap.Addr()
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() ||
		a == netip.MustParseAddr("100.100.100.100") ||
		netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(a) ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a) || r.seen[a] {
		return
	}
	if r.seen == nil {
		r.seen = map[netip.Addr]bool{}
	}
	r.seen[a] = true
	r.out = append(r.out, a)
}

// parseResolvectl reads `resolvectl dns` output, ignoring the Tailscale and
// tunnel links.
func parseResolvectl(out string) []netip.Addr {
	var r resolverSet
	for _, line := range strings.Split(out, "\n") {
		var label, rest string
		if i := strings.Index(line, "):"); i >= 0 {
			label, rest = line[:i+1], line[i+2:]
		} else if strings.HasPrefix(line, "Global:") {
			label, rest = "Global", strings.TrimPrefix(line, "Global:")
		} else {
			continue
		}
		if strings.Contains(label, "(tailscale") || strings.Contains(label, "("+Interface+")") {
			continue
		}
		for _, f := range strings.Fields(rest) {
			r.add(f)
		}
	}
	return r.out
}

func parseResolvConf(text string) []netip.Addr {
	var r resolverSet
	for _, line := range strings.Split(text, "\n") {
		if fs := strings.Fields(line); len(fs) >= 2 && fs[0] == "nameserver" {
			r.add(fs[1])
		}
	}
	return r.out
}

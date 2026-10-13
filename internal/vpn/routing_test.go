package vpn

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestRules(t *testing.T) {
	var n Router
	mark := fmt.Sprintf("fwmark 0x%x lookup %d", FWMark, Table)
	exit := fmt.Sprintf("iif tailscale0 lookup %d", Table)

	t.Run("full v4 setup", func(t *testing.T) {
		d := Desired{Exit4: true, Block4: true, DNS: addrs("1.1.1.1", "2606:4700::1111"), TunnelAddrs: addrs("10.2.0.2")}
		r := n.rules(d, false)
		want := map[int]string{
			prefMark:    mark,
			prefDNSBase: fmt.Sprintf("to 1.1.1.1 lookup %d", Table),
			prefSrc:     fmt.Sprintf("from 10.2.0.2 lookup %d", Table),
			prefExit:    exit,
			prefBlock:   "iif tailscale0 prohibit",
		}
		if len(r) != len(want) {
			t.Fatalf("rules = %v, want %v", r, want)
		}
		for p, w := range want {
			if r[p] != w {
				t.Errorf("pref %d = %q, want %q", p, r[p], w)
			}
		}
	})

	t.Run("v6 family only gets v6 entries", func(t *testing.T) {
		d := Desired{Exit4: true, Block6: true, DNS: addrs("1.1.1.1", "2606:4700::1111"), TunnelAddrs: addrs("10.2.0.2")}
		r := n.rules(d, true)
		if _, ok := r[prefExit]; ok {
			t.Error("v6 exit rule present though Exit6 is false")
		}
		if r[prefBlock] != "iif tailscale0 prohibit" {
			t.Error("v6 block rule missing")
		}
		if r[prefDNSBase] != fmt.Sprintf("to 2606:4700::1111 lookup %d", Table) {
			t.Errorf("v6 DNS rule = %q", r[prefDNSBase])
		}
		if _, ok := r[prefSrc]; ok {
			t.Error("v6 source rule present without a v6 tunnel address")
		}
	})

	t.Run("forwarded UDP replies are routed by source port", func(t *testing.T) {
		want := fmt.Sprintf("ipproto udp sport 40000 lookup %d", Table)
		if r := n.rules(Desired{PFPort: 40000, PFInternal: 1}, false); r[prefSport] != want {
			t.Errorf("local forward: %q, want %q", r[prefSport], want)
		}
		if r := n.rules(Desired{PFPort: 40000, PFTargetPort: 6881}, false); r[prefSport] != fmt.Sprintf("ipproto udp sport 6881 lookup %d", Table) {
			t.Errorf("custom local port: %q", r[prefSport])
		}
		// Forwarding to a tailnet device: replies come back via tailscale0
		// and the exit rule already sends them into the tunnel.
		if r := n.rules(Desired{PFPort: 40000, PFTarget: "100.1.2.3"}, false); r[prefSport] != "" {
			t.Errorf("tailnet target should not add a sport rule: %q", r[prefSport])
		}
		if r := n.rules(Desired{PFPort: 40000}, true); r[prefSport] != "" {
			t.Errorf("no v6 sport rule: %q", r[prefSport])
		}
	})

	t.Run("direct mode keeps only the mark rule", func(t *testing.T) {
		r := n.rules(Desired{}, false)
		if len(r) != 1 || r[prefMark] != mark {
			t.Errorf("rules = %v", r)
		}
	})

	t.Run("DNS rules are capped to the reserved range", func(t *testing.T) {
		var many []netip.Addr
		for i := 1; i <= 12; i++ {
			many = append(many, netip.AddrFrom4([4]byte{9, 9, 9, byte(i)}))
		}
		r := n.rules(Desired{DNS: many}, false)
		count := 0
		for p := range r {
			if p >= prefDNSBase && p <= prefDNSMax {
				count++
			}
		}
		if count != prefDNSMax-prefDNSBase+1 {
			t.Errorf("%d DNS rules, want %d", count, prefDNSMax-prefDNSBase+1)
		}
		for p := range r {
			if p > prefDNSMax && p < prefSrc {
				t.Errorf("DNS rule spilled into pref %d", p)
			}
		}
	})
}

func TestFirewallPayload(t *testing.T) {
	has := func(t *testing.T, p string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(p, w) {
				t.Errorf("missing %q in:\n%s", w, p)
			}
		}
	}
	hasNot := func(t *testing.T, p string, bad ...string) {
		t.Helper()
		for _, b := range bad {
			if strings.Contains(p, b) {
				t.Errorf("unexpected %q in:\n%s", b, p)
			}
		}
	}

	t.Run("baseline protections", func(t *testing.T) {
		p := firewallPayload(Desired{}, false)
		has(t, p,
			"-A PE-INPUT -i pvpn0 -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT",
			"-A PE-INPUT -i pvpn0 -j DROP",
			"-A PE-FORWARD -i pvpn0 -j DROP",
			"-A PE-POST -o pvpn0 -j MASQUERADE",
			"--clamp-mss-to-pmtu",
			"*filter", "*nat", "*mangle")
		if strings.Count(p, "COMMIT") != 3 {
			t.Error("each table needs a COMMIT")
		}
		hasNot(t, p, "DNAT --to", "REDIRECT")
	})

	t.Run("forward to a tailnet device", func(t *testing.T) {
		p := firewallPayload(Desired{PFPort: 40000, PFInternal: 1, PFTarget: "100.1.2.3", PFTargetPort: 8080}, false)
		has(t, p,
			"-p tcp -m tcp --dport 1 -j DNAT --to-destination 100.1.2.3:8080",
			"-p udp -m udp --dport 1 -j DNAT --to-destination 100.1.2.3:8080",
			"-A PE-POST -o tailscale0 -d 100.1.2.3 -m conntrack --ctstate DNAT -j MASQUERADE")
		hasNot(t, p, "--dport 40000 -j ACCEPT")
	})

	t.Run("Proton delivers to port 1: redirect to the public port", func(t *testing.T) {
		p := firewallPayload(Desired{PFPort: 40000, PFInternal: 1}, false)
		has(t, p, "-p tcp -m tcp --dport 1 -j REDIRECT --to-ports 40000", "-p udp -m udp --dport 1 -j REDIRECT --to-ports 40000")
	})

	t.Run("local port already matches: plain accept", func(t *testing.T) {
		p := firewallPayload(Desired{PFPort: 40000, PFInternal: 40000}, false)
		has(t, p, "-A PE-INPUT -i pvpn0 -p tcp -m tcp --dport 40000 -j ACCEPT", "-A PE-INPUT -i pvpn0 -p udp -m udp --dport 40000 -j ACCEPT")
		hasNot(t, p, "REDIRECT", "DNAT --to")
	})

	t.Run("custom local port", func(t *testing.T) {
		p := firewallPayload(Desired{PFPort: 40000, PFInternal: 1, PFTargetPort: 6881}, false)
		has(t, p, "--dport 1 -j REDIRECT --to-ports 6881")
	})

	t.Run("ipv6", func(t *testing.T) {
		p := firewallPayload(Desired{PFPort: 40000, PFInternal: 1}, true)
		hasNot(t, p, "40000", "MASQUERADE")
		has(t, p, "-A PE-INPUT -i pvpn0 -j DROP")
		p = firewallPayload(Desired{TunnelV6: true}, true)
		has(t, p, "-A PE-POST -o pvpn0 -j MASQUERADE")
	})
}

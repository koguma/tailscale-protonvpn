package vpn

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseResolvectl(t *testing.T) {
	// Real output from a Debian host running Tailscale with MagicDNS.
	out := "Global:\nLink 2 (eth0): 1.1.1.1\nLink 3 (tailscale0): 100.100.100.100 fd7a:115c:a1e0::53\n"
	if got := parseResolvectl(out); len(got) != 1 || got[0] != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("got %v, want [1.1.1.1]", got)
	}

	out = strings.Join([]string{
		"Global: 9.9.9.9#dns.quad9.net 2620:fe::fe%eth0 127.0.0.53",
		"Link 2 (ens3): 192.0.2.53:53 9.9.9.9 fe80::1",
		"Link 4 (pvpn0): 10.2.0.1",
		"Link 5 (tailscale0): 100.100.100.100",
		"garbage line",
	}, "\n")
	got := parseResolvectl(out)
	want := addrs("9.9.9.9", "2620:fe::fe", "192.0.2.53")
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseResolvConf(t *testing.T) {
	conf := "# managed\nnameserver 100.100.100.100\nnameserver 8.8.8.8\nnameserver 127.0.0.53\nsearch example.ts.net\nnameserver 2001:4860:4860::8888\n"
	got := parseResolvConf(conf)
	if len(got) != 2 || got[0] != netip.MustParseAddr("8.8.8.8") || got[1] != netip.MustParseAddr("2001:4860:4860::8888") {
		t.Errorf("got %v", got)
	}
}

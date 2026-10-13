package controller

import (
	"sort"
	"testing"
)

func TestCountryCode(t *testing.T) {
	for _, c := range []struct {
		name string
		sc   bool
		want string
	}{
		{"US-CA#12", false, "US"},
		{"CH-US#1", true, "US"}, // Secure Core: entry CH, exit US
		{"UK#3", false, "GB"},
		{"FR#13-TOR", false, "FR"},
		{"CA-FREE#2", false, "CA"},
		{"DE#435", false, "DE"},
	} {
		if got := countryCode(c.name, c.sc); got != c.want {
			t.Errorf("countryCode(%q, %v) = %q, want %q", c.name, c.sc, got, c.want)
		}
	}
}

func TestNaturalLess(t *testing.T) {
	names := []string{"CH#10", "CH#2", "AT#1", "CH#1", "CH#13-TOR"}
	sort.Slice(names, func(i, j int) bool { return naturalLess(names[i], names[j]) })
	want := []string{"AT#1", "CH#1", "CH#2", "CH#10", "CH#13-TOR"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("sorted = %v, want %v", names, want)
		}
	}
}

func TestParseCatalog(t *testing.T) {
	raw := `{"version":4,"timestamp":1700000000,"servers":[
	  {"vpn":"openvpn","country":"Switzerland","server_name":"CH#1","hostname":"ch-01","ips":["9.9.9.9"]},
	  {"vpn":"wireguard","country":"Switzerland","city":"Zurich","server_name":"CH#10","hostname":"ch-10","wgpubkey":"k1","port_forward":true,"ips":["1.1.1.10"]},
	  {"vpn":"wireguard","country":"Switzerland","city":"Zurich","server_name":"CH#2","hostname":"ch-02","wgpubkey":"k2","stream":true,"ips":["1.1.1.2","1.1.1.3"]},
	  {"vpn":"wireguard","country":"Austria","city":"Vienna","server_name":"AT#1","hostname":"at-01","wgpubkey":"k3","ips":["1.1.1.10"]},
	  {"vpn":"wireguard","country":"United States","city":"Chicago","server_name":"CH-US#1","hostname":"sc","wgpubkey":"k4","secure_core":true,"ips":["2.2.2.2"]},
	  {"vpn":"wireguard","country":"France","server_name":"FR#1","hostname":"nokey","ips":["3.3.3.3"]}
	]}`
	s, ts, err := parseCatalog([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if ts.Unix() != 1700000000 {
		t.Errorf("timestamp = %v", ts)
	}
	var names []string
	for _, x := range s {
		names = append(names, x.Name+"@"+x.IP)
	}
	// openvpn and key-less entries dropped; the duplicate IP keeps its first
	// owner (CH#10); sorted by country, then naturally by name.
	want := []string{"CH#2@1.1.1.2", "CH#2@1.1.1.3", "CH#10@1.1.1.10", "CH-US#1@2.2.2.2"}
	if len(names) != len(want) {
		t.Fatalf("servers = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("servers = %v, want %v", names, want)
		}
	}
	byName := map[string]Server{}
	for _, x := range s {
		byName[x.Name] = x
	}
	if !byName["CH#10"].P2P || byName["CH#2"].P2P || !byName["CH#2"].Streaming {
		t.Error("feature flags not mapped")
	}
	if sc := byName["CH-US#1"]; !sc.SecureCore || sc.CC != "US" {
		t.Errorf("secure core server = %+v", sc)
	}
	if _, _, err := parseCatalog([]byte("not json")); err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestEmbeddedCatalog(t *testing.T) {
	s, _, err := parseCatalog(serverSnapshot)
	if err != nil || len(s) < 500 {
		t.Fatalf("serverSnapshot: %d servers, err %v", len(s), err)
	}
	p2p := 0
	for _, x := range s {
		if x.IP == "" || x.PubKey == "" || len(x.CC) != 2 {
			t.Fatalf("incomplete server %+v", x)
		}
		if x.P2P {
			p2p++
		}
	}
	if p2p == 0 {
		t.Error("no P2P servers in serverSnapshot")
	}
}

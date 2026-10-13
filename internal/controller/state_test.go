package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConf = `[Interface]
# Key for my-server
# Bouncing = 1
# NetShield = 1
# Moderate NAT = off
# NAT-PMP (Port Forwarding) = on
# VPN Accelerator = on
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1

[Peer]
# AF#1
PublicKey = RY8jot0tZvug/zGd4SDBa5yFlMvhzYEto55QfMPSTG0=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 79.135.105.1:51820
`

const testKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

func TestParseWGConfig(t *testing.T) {
	k, peer, err := ParseWGConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	if k.PrivateKey != testKey {
		t.Errorf("private key = %q (base64 padding must survive the '=' split)", k.PrivateKey)
	}
	if k.Label != "my-server" {
		t.Errorf("label = %q", k.Label)
	}
	if k.NATPMP == nil || !*k.NATPMP {
		t.Errorf("NAT-PMP comment not detected: %v", k.NATPMP)
	}
	if got := strings.Join(k.Addresses, ","); got != "10.2.0.2/32,2a07:b944::2:2/128" {
		t.Errorf("addresses = %s", got)
	}
	if !k.HasV6() {
		t.Error("HasV6 = false for a config with an IPv6 address")
	}
	if peer == nil || peer.IP != "79.135.105.1" || peer.PubKey != "RY8jot0tZvug/zGd4SDBa5yFlMvhzYEto55QfMPSTG0=" {
		t.Errorf("peer = %+v", peer)
	}
}

func TestParseWGConfigVariants(t *testing.T) {
	t.Run("minimal config gets Proton's default address", func(t *testing.T) {
		k, peer, err := ParseWGConfig("[Interface]\nPrivateKey = " + testKey + "\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(k.Addresses) != 1 || k.Addresses[0] != "10.2.0.2/32" || k.HasV6() {
			t.Errorf("addresses = %v", k.Addresses)
		}
		if k.NATPMP != nil {
			t.Errorf("NAT-PMP should be unknown, got %v", *k.NATPMP)
		}
		if peer != nil {
			t.Errorf("peer = %+v, want nil", peer)
		}
	})
	t.Run("NAT-PMP off", func(t *testing.T) {
		k, _, err := ParseWGConfig("[Interface]\n# NAT-PMP (Port Forwarding) = off\nPrivateKey = " + testKey + "\n")
		if err != nil || k.NATPMP == nil || *k.NATPMP {
			t.Fatalf("natpmp = %v, err %v", k.NATPMP, err)
		}
	})
	t.Run("bare address gets a host prefix", func(t *testing.T) {
		k, _, err := ParseWGConfig("[Interface]\nPrivateKey = " + testKey + "\nAddress = 10.2.0.2, 2a07:b944::2:2\n")
		if err != nil || strings.Join(k.Addresses, ",") != "10.2.0.2/32,2a07:b944::2:2/128" {
			t.Fatalf("addresses = %v, err %v", k.Addresses, err)
		}
	})
	for name, conf := range map[string]string{
		"no key":      "[Interface]\nAddress = 10.2.0.2/32\n",
		"bad key":     "[Interface]\nPrivateKey = nope\n",
		"bad address": "[Interface]\nPrivateKey = " + testKey + "\nAddress = 10.2.0/32\n",
		"empty":       "",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, _, err := ParseWGConfig(conf); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "state.json"))

	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st != DefaultState() {
		t.Errorf("missing file should give defaults, got %+v", st)
	}
	if !st.KillSwitch || !st.DNSViaVPN || !st.PortForward || st.Enabled {
		t.Errorf("unexpected defaults %+v", st)
	}

	st.Enabled = true
	st.Key = &WGKey{PrivateKey: testKey, Addresses: []string{"10.2.0.2/32"}}
	st.Server = &Server{ID: "1.2.3.4", Name: "CH#1", IP: "1.2.3.4", PubKey: "x"}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v, want 0600 (it holds the private key)", fi.Mode().Perm())
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Key.PrivateKey != testKey || got.Server.Name != "CH#1" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".state-*")); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

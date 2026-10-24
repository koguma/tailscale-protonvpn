package controller

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestTunnelPhase(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name      string
		err       error
		handshake time.Time
		since     time.Time
		phase     string
		healthy   bool
	}{
		{"fresh handshake", nil, now.Add(-30 * time.Second), now.Add(-time.Hour), "connected", true},
		{"just switched, no handshake yet", nil, time.Time{}, now.Add(-5 * time.Second), "connecting", false},
		{"no handshake after grace", nil, time.Time{}, now.Add(-time.Minute), "stalled", false},
		{"handshake went stale", nil, now.Add(-4 * time.Minute), now.Add(-time.Hour), "stalled", false},
		{"interface error", errors.New("boom"), now, now, "error", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			phase, msg, healthy := tunnelPhase(c.err, c.handshake, c.since, now)
			if phase != c.phase || healthy != c.healthy {
				t.Errorf("got %s/%v, want %s/%v", phase, healthy, c.phase, c.healthy)
			}
			if (phase == "stalled" || phase == "error") && msg == "" {
				t.Error("problem phases need a message for the dashboard")
			}
		})
	}
}

func keyWith(addrs ...string) *WGKey {
	return &WGKey{PrivateKey: testKey, Addresses: addrs}
}

// TestKillSwitchMatrix checks every combination of tunnel health, kill switch
// and tunnel IPv6 against the guarantees the README makes.
func TestKillSwitchMatrix(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		for _, ks := range []bool{true, false} {
			for _, v6 := range []bool{true, false} {
				key := keyWith("10.2.0.2/32")
				if v6 {
					key = keyWith("10.2.0.2/32", "2a07:b944::2:2/128")
				}
				st := State{Enabled: true, KillSwitch: ks, Key: key}
				d := desiredNet(st, healthy, 0, 0)
				name := map[bool]string{true: "healthy", false: "down"}[healthy] +
					map[bool]string{true: "+killswitch", false: ""}[ks] +
					map[bool]string{true: "+v6", false: ""}[v6]

				// v4: healthy tunnel always carries exit traffic.
				if healthy && !d.Exit4 {
					t.Errorf("%s: exit traffic not routed into a healthy tunnel", name)
				}
				// Kill switch: traffic never falls through to the uplink.
				if ks && !(d.Exit4 && d.Block4) {
					t.Errorf("%s: kill switch must keep exit rule and block rule (exit=%v block=%v)", name, d.Exit4, d.Block4)
				}
				// No kill switch + dead tunnel: fall back to direct.
				if !ks && !healthy && (d.Exit4 || d.Block4) {
					t.Errorf("%s: expected direct fallback (exit=%v block=%v)", name, d.Exit4, d.Block4)
				}
				// IPv6 can never bypass the VPN when the tunnel has no v6.
				if !v6 && (d.Exit6 || !d.Block6) {
					t.Errorf("%s: IPv6 must be blocked without tunnel IPv6 (exit6=%v block6=%v)", name, d.Exit6, d.Block6)
				}
				if v6 && d.Exit6 != d.Exit4 {
					t.Errorf("%s: v6 should follow v4 when the tunnel has IPv6", name)
				}
				if d.TunnelV6 != v6 {
					t.Errorf("%s: TunnelV6 = %v", name, d.TunnelV6)
				}
			}
		}
	}
}

func TestDesiredNetExtras(t *testing.T) {
	st := State{Enabled: true, DNSViaVPN: true, PortForward: true, PFTarget: "100.1.2.3", PFTargetPort: 8080, Key: keyWith("10.2.0.2/32")}

	d := desiredNet(st, true, 40000, 1)
	if !d.DNS || d.DNSBlock || d.PFPort != 40000 || d.PFInternal != 1 || d.PFTarget != "100.1.2.3" || d.PFTargetPort != 8080 {
		t.Errorf("healthy: %+v", d)
	}
	if len(d.TunnelAddrs) != 1 || d.TunnelAddrs[0] != netip.MustParseAddr("10.2.0.2") {
		t.Errorf("tunnel addrs = %v", d.TunnelAddrs)
	}

	// A dead tunnel must not pull DNS or port forwarding into it. Without the
	// kill switch exit clients' DNS goes direct; with it, it is blocked.
	if d := desiredNet(st, false, 40000, 1); d.DNS || d.DNSBlock || d.PFPort != 0 {
		t.Errorf("unhealthy: %+v", d)
	}
	ks := st
	ks.KillSwitch = true
	if d := desiredNet(ks, false, 40000, 1); d.DNS || !d.DNSBlock {
		t.Errorf("unhealthy + kill switch: DNS=%v DNSBlock=%v", d.DNS, d.DNSBlock)
	}

	off := ks
	off.DNSViaVPN, off.PortForward = false, false
	for _, healthy := range []bool{true, false} {
		if d := desiredNet(off, healthy, 40000, 1); d.DNS || d.DNSBlock || (healthy && d.PFPort != 0) {
			t.Errorf("features off (healthy=%v): %+v", healthy, d)
		}
	}
}

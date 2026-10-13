package vpn

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Interface is the WireGuard interface tailscale-protonvpn owns.
const Interface = "pvpn0"

const keepalive = 25 * time.Second

// TunnelConfig is what the tunnel needs: our key/addresses and the server peer.
type TunnelConfig struct {
	PrivateKey string
	Addresses  []string
	PeerKey    string
	PeerIP     string
}

// TunnelExists reports whether the WireGuard interface is present.
func TunnelExists() bool {
	_, err := net.InterfaceByName(Interface)
	return err == nil
}

// DeleteTunnel removes the interface (and with it its routes).
func DeleteTunnel() {
	if TunnelExists() {
		Run("ip", "link", "del", Interface)
	}
}

// EnsureTunnel creates/updates the kernel WireGuard interface. It reports
// whether the peer changed (i.e. a new server was selected), so callers can
// reset connection-dependent status. Switching servers only swaps the peer on
// the existing interface, so the kill switch never has a gap.
func EnsureTunnel(wg *wgctrl.Client, cfg TunnelConfig) (peerChanged bool, err error) {
	if !TunnelExists() {
		if _, err := Run("ip", "link", "add", Interface, "type", "wireguard"); err != nil {
			return false, err
		}
		Run("ip", "link", "set", Interface, "mtu", "1420")
	}
	// Loose reverse-path filtering: replies arrive on pvpn0 from addresses the
	// main table would route via the default uplink.
	os.WriteFile("/proc/sys/net/ipv4/conf/"+Interface+"/rp_filter", []byte("2"), 0o644)

	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return false, fmt.Errorf("private key: %w", err)
	}
	pub, err := wgtypes.ParseKey(cfg.PeerKey)
	if err != nil {
		return false, fmt.Errorf("server public key: %w", err)
	}
	ip := net.ParseIP(cfg.PeerIP)
	if ip == nil {
		return false, fmt.Errorf("bad server IP %q", cfg.PeerIP)
	}
	endpoint := &net.UDPAddr{IP: ip, Port: 51820}

	dev, err := wg.Device(Interface)
	if err != nil {
		return false, err
	}
	// Compare public keys: the kernel clamps private keys, so a raw
	// private-key comparison can differ even for the same key.
	same := dev.PublicKey == priv.PublicKey() && len(dev.Peers) == 1 &&
		dev.Peers[0].PublicKey == pub && dev.Peers[0].Endpoint != nil &&
		dev.Peers[0].Endpoint.String() == endpoint.String()
	if !same {
		_, all4, _ := net.ParseCIDR("0.0.0.0/0")
		_, all6, _ := net.ParseCIDR("::/0")
		ka := keepalive
		err := wg.ConfigureDevice(Interface, wgtypes.Config{
			PrivateKey:   &priv,
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey:                   pub,
				Endpoint:                    endpoint,
				AllowedIPs:                  []net.IPNet{*all4, *all6},
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: &ka,
			}},
		})
		if err != nil {
			return false, fmt.Errorf("configure wireguard: %w", err)
		}
		peerChanged = true
	}

	if err := syncAddresses(cfg.Addresses); err != nil {
		return peerChanged, err
	}
	if ifc, err := net.InterfaceByName(Interface); err == nil && ifc.Flags&net.FlagUp == 0 {
		if _, err := Run("ip", "link", "set", Interface, "up"); err != nil {
			return peerChanged, err
		}
	}
	return peerChanged, nil
}

func syncAddresses(want []string) error {
	ifc, err := net.InterfaceByName(Interface)
	if err != nil {
		return err
	}
	addrs, _ := ifc.Addrs()
	have := map[string]bool{}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
			have[n.String()] = true
		}
	}
	wantSet := map[string]bool{}
	for _, a := range want {
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		ip, _, _ := net.ParseCIDR(a)
		n.IP = ip
		wantSet[n.String()] = true
		if !have[n.String()] {
			if _, err := Run("ip", "addr", "add", n.String(), "dev", Interface); err != nil {
				return err
			}
		}
	}
	for a := range have {
		if !wantSet[a] {
			Run("ip", "addr", "del", a, "dev", Interface)
		}
	}
	return nil
}

type Stats struct {
	Handshake time.Time
	RX, TX    int64
}

// ReadStats returns handshake and traffic counters for the (single) peer.
func ReadStats(wg *wgctrl.Client) (Stats, error) {
	dev, err := wg.Device(Interface)
	if err != nil {
		return Stats{}, err
	}
	if len(dev.Peers) == 0 {
		return Stats{}, nil
	}
	p := dev.Peers[0]
	return Stats{Handshake: p.LastHandshakeTime, RX: p.ReceiveBytes, TX: p.TransmitBytes}, nil
}

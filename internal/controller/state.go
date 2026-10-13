package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// State is everything the user configures. It is persisted so the exit node
// comes back exactly as it was after a reboot.
type State struct {
	Enabled      bool    `json:"enabled"`
	KillSwitch   bool    `json:"killSwitch"`
	DNSViaVPN    bool    `json:"dnsViaVPN"`
	PortForward  bool    `json:"portForward"`
	PFTarget     string  `json:"pfTarget"`     // tailnet IP to DNAT the forwarded port to; "" = this machine
	PFTargetPort int     `json:"pfTargetPort"` // 0 = same as the public port
	Server       *Server `json:"server,omitempty"`
	Key          *WGKey  `json:"key,omitempty"`
}

// WGKey is the [Interface] half of a ProtonVPN WireGuard  Proton keys
// are account-wide, so one key works with every server in the
type WGKey struct {
	PrivateKey string   `json:"privateKey"`
	Addresses  []string `json:"addresses"`
	NATPMP     *bool    `json:"natpmp,omitempty"` // from the "# NAT-PMP (Port Forwarding) = on" comment, if present
	Label      string   `json:"label,omitempty"`
}

func (k *WGKey) HasV6() bool {
	for _, a := range k.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is6() {
			return true
		}
	}
	return false
}

// DefaultState returns the settings for a fresh install.
func DefaultState() State {
	return State{KillSwitch: true, DNSViaVPN: true, PortForward: true}
}

// Store persists State as JSON. The file holds the WireGuard private key, so
// it is written with mode 0600.
type Store struct{ path string }

// NewStore returns a Store backed by the file at path.
func NewStore(path string) *Store { return &Store{path: path} }

// Path returns the state file location.
func (s *Store) Path() string { return s.path }

func (s *Store) Load() (State, error) {
	st := DefaultState()
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (s *Store) Save(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// ParseWGConfig extracts the key, addresses and (if present) peer from a
// WireGuard config as downloaded from account.protonvpn.com.
func ParseWGConfig(text string) (*WGKey, *Server, error) {
	key := &WGKey{}
	var section, peerPub, endpoint string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			c := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if k, v, ok := strings.Cut(c, "="); ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(k)), "nat-pmp") {
				v = strings.ToLower(strings.TrimSpace(v))
				on := v == "on" || v == "1" || v == "true"
				key.NATPMP = &on
			}
			if section == "interface" && strings.HasPrefix(strings.ToLower(c), "key for ") {
				key.Label = strings.TrimSpace(c[len("key for "):])
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			key.PrivateKey = v
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if a == "" {
					continue
				}
				if !strings.Contains(a, "/") {
					if strings.Contains(a, ":") {
						a += "/128"
					} else {
						a += "/32"
					}
				}
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, nil, fmt.Errorf("bad Address %q", a)
				}
				key.Addresses = append(key.Addresses, p.String())
			}
		case "peer.publickey":
			peerPub = v
		case "peer.endpoint":
			endpoint = v
		}
	}
	if key.PrivateKey == "" {
		return nil, nil, errors.New("no PrivateKey found in [Interface] section")
	}
	if _, err := wgtypes.ParseKey(key.PrivateKey); err != nil {
		return nil, nil, fmt.Errorf("invalid PrivateKey: %v", err)
	}
	if len(key.Addresses) == 0 {
		key.Addresses = []string{"10.2.0.2/32"} // what Proton always hands out
	}

	var peer *Server
	if peerPub != "" && endpoint != "" {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			host = endpoint
		}
		if ip := net.ParseIP(host); ip != nil {
			if _, err := wgtypes.ParseKey(peerPub); err == nil {
				peer = &Server{ID: ip.String(), Name: "From config", IP: ip.String(), PubKey: peerPub, Country: "Custom"}
			}
		}
	}
	return key, peer, nil
}

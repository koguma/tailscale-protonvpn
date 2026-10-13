package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// NAT-PMP opcodes for mapping requests.
const (
	ProtoUDP byte = 1
	ProtoTCP byte = 2
)

const natpmpPort = 5351

// RequestPort asks Proton's gateway, through the tunnel, for a NAT-PMP port
// mapping (RFC 6886) and returns the (public, internal) ports. Proton keys
// mappings on the internal port and returns the same public port for repeated
// requests, so we always ask exactly like Proton's docs (natpmpc -a 1 0);
// asking for any other internal port allocates an extra mapping and soon
// exhausts the quota (result code 4).
func RequestPort(proto byte, lifetime uint32) (public, internal int, err error) {
	c, err := dialTunnel("udp4", net.JoinHostPort(Gateway, strconv.Itoa(natpmpPort)))
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	return natpmpExchange(c, proto, 1, 0, lifetime, 250*time.Millisecond)
}

// natpmpExchange sends one mapping request over c, retrying with exponential
// backoff as RFC 6886 recommends, and returns the (public, internal) ports.
func natpmpExchange(c net.Conn, op byte, internal, external int, lifetime uint32, timeout time.Duration) (int, int, error) {
	req := make([]byte, 12)
	req[1] = op
	binary.BigEndian.PutUint16(req[4:], uint16(internal))
	binary.BigEndian.PutUint16(req[6:], uint16(external))
	binary.BigEndian.PutUint32(req[8:], lifetime)

	resp := make([]byte, 16)
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := c.Write(req); err != nil {
			return 0, 0, err
		}
		c.SetReadDeadline(time.Now().Add(timeout))
		n, err := c.Read(resp)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				timeout *= 2
				continue
			}
			return 0, 0, err
		}
		if n < 16 || resp[0] != 0 || resp[1] != op+128 {
			return 0, 0, errors.New("nat-pmp: malformed response")
		}
		if rc := binary.BigEndian.Uint16(resp[2:]); rc != 0 {
			return 0, 0, fmt.Errorf("nat-pmp: %s (result code %d)", natpmpResult(rc), rc)
		}
		return int(binary.BigEndian.Uint16(resp[10:])), int(binary.BigEndian.Uint16(resp[8:])), nil
	}
	return 0, 0, errors.New("nat-pmp: no response from gateway")
}

func natpmpResult(rc uint16) string {
	switch rc {
	case 1:
		return "unsupported version"
	case 2:
		return "not authorized - the key needs NAT-PMP (port forwarding) enabled"
	case 3:
		return "gateway network failure"
	case 4:
		return "gateway out of mapping resources"
	case 5:
		return "unsupported opcode"
	}
	return "gateway refused"
}

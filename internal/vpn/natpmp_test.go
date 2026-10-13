package vpn

import (
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGateway answers NAT-PMP mapping requests on localhost. handle gets each
// request and returns the response to send (nil = stay silent).
func fakeGateway(t *testing.T, handle func(n int, req []byte) []byte) net.Conn {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		buf := make([]byte, 64)
		for n := 1; ; n++ {
			l, from, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := handle(n, append([]byte(nil), buf[:l]...)); resp != nil {
				srv.WriteToUDP(resp, from)
			}
		}
	}()
	c, err := net.Dial("udp4", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func mappingResponse(req []byte, result uint16, public uint16) []byte {
	resp := make([]byte, 16)
	resp[1] = req[1] + 128
	binary.BigEndian.PutUint16(resp[2:], result)
	binary.BigEndian.PutUint32(resp[4:], 12345) // seconds since epoch
	copy(resp[8:10], req[4:6])                  // internal port echoed back
	binary.BigEndian.PutUint16(resp[10:], public)
	binary.BigEndian.PutUint32(resp[12:], binary.BigEndian.Uint32(req[8:]))
	return resp
}

func TestNATPMPRequestFormat(t *testing.T) {
	reqs := make(chan []byte, 1)
	c := fakeGateway(t, func(_ int, req []byte) []byte {
		reqs <- req
		return mappingResponse(req, 0, 48081)
	})
	pub, internal, err := natpmpExchange(c, 2, 1, 0, 60, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if pub != 48081 || internal != 1 {
		t.Errorf("got public %d internal %d", pub, internal)
	}
	// version 0, opcode 2 (TCP), reserved, internal 1, external 0, lifetime 60:
	// exactly what `natpmpc -a 1 0 tcp 60` sends, the form Proton keeps stable.
	want := []byte{0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 60}
	if got := <-reqs; string(got) != string(want) {
		t.Errorf("request = %v, want %v", got, want)
	}
}

func TestNATPMPErrors(t *testing.T) {
	t.Run("result code 4", func(t *testing.T) {
		c := fakeGateway(t, func(_ int, req []byte) []byte { return mappingResponse(req, 4, 0) })
		_, _, err := natpmpExchange(c, 1, 1, 0, 60, 200*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "out of mapping resources") || !strings.Contains(err.Error(), "code 4") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("not authorized hints at NAT-PMP", func(t *testing.T) {
		c := fakeGateway(t, func(_ int, req []byte) []byte { return mappingResponse(req, 2, 0) })
		_, _, err := natpmpExchange(c, 1, 1, 0, 60, 200*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "NAT-PMP") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("wrong opcode in reply", func(t *testing.T) {
		c := fakeGateway(t, func(_ int, req []byte) []byte {
			r := mappingResponse(req, 0, 1)
			r[1] = 129 // UDP reply to a TCP request
			return r
		})
		if _, _, err := natpmpExchange(c, 2, 1, 0, 60, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("silent gateway", func(t *testing.T) {
		var calls atomic.Int32
		c := fakeGateway(t, func(n int, _ []byte) []byte { calls.Store(int32(n)); return nil })
		start := time.Now()
		_, _, err := natpmpExchange(c, 1, 1, 0, 60, 5*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "no response") {
			t.Errorf("err = %v", err)
		}
		if n := calls.Load(); n != 5 {
			t.Errorf("%d attempts, want 5", n)
		}
		if time.Since(start) < 150*time.Millisecond { // 5+10+20+40+80 ms of backoff
			t.Error("retries didn't back off")
		}
	})
	t.Run("retries after a lost packet", func(t *testing.T) {
		c := fakeGateway(t, func(n int, req []byte) []byte {
			if n == 1 {
				return nil
			}
			return mappingResponse(req, 0, 50000)
		})
		if pub, _, err := natpmpExchange(c, 1, 1, 0, 60, 20*time.Millisecond); err != nil || pub != 50000 {
			t.Errorf("pub %d err %v", pub, err)
		}
	})
}

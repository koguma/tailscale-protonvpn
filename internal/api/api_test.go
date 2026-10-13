package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koguma/tailscale-protonvpn/internal/controller"
)

// newTestAPI wires the real handlers to a controller whose reconcile is a
// no-op, so tests never touch the host's network.
type testEnv struct {
	*controller.Controller
	cat   *controller.Catalog
	store *controller.Store
}

func newTestAPI(t *testing.T, users ...string) (http.Handler, testEnv) {
	t.Helper()
	dir := t.TempDir()
	store := controller.NewStore(filepath.Join(dir, "state.json"))
	cat := controller.NewCatalog(filepath.Join(dir, "servers.json"))
	c, err := controller.New(store, controller.DefaultState(), cat, controller.WithoutNetwork())
	if err != nil {
		t.Fatal(err)
	}
	return New(c, cat, users, "test"), testEnv{c, cat, store}
}

const testKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

const sampleConf = `[Interface]
# NAT-PMP (Port Forwarding) = on
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.2.0.2/32

[Peer]
PublicKey = RY8jot0tZvug/zGd4SDBa5yFlMvhzYEto55QfMPSTG0=
Endpoint = 79.135.105.1:51820
`

func do(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if method != http.MethodGet {
		req.Header.Set("X-Tailscale-Protonvpn", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func confJSON(conf string) string {
	b, _ := json.Marshal(map[string]string{"config": conf})
	return string(b)
}

func TestAPIRequiresCSRFHeader(t *testing.T) {
	h, _ := newTestAPI(t)
	rec, _ := do(t, h, "POST", "/api/state", `{"killSwitch":false}`, map[string]string{"X-Tailscale-Protonvpn": ""})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without X-Tailscale-Protonvpn: %d, want 403", rec.Code)
	}
	if rec, _ := do(t, h, "GET", "/api/status", "", nil); rec.Code != 200 {
		t.Errorf("GET status: %d", rec.Code)
	}
}

func TestAPIAllowUsers(t *testing.T) {
	h, _ := newTestAPI(t, "alice@example.com")
	if rec, _ := do(t, h, "GET", "/api/status", "", nil); rec.Code != http.StatusForbidden {
		t.Errorf("no identity: %d, want 403", rec.Code)
	}
	if rec, _ := do(t, h, "GET", "/api/status", "", map[string]string{"Tailscale-User-Login": "mallory@example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("wrong user: %d, want 403", rec.Code)
	}
	if rec, _ := do(t, h, "GET", "/api/status", "", map[string]string{"Tailscale-User-Login": "Alice@Example.com"}); rec.Code != 200 {
		t.Errorf("allowed user (case-insensitive): %d, want 200", rec.Code)
	}
}

func TestAPIEnableFlow(t *testing.T) {
	h, c := newTestAPI(t)

	rec, m := do(t, h, "POST", "/api/state", `{"enabled":true}`, nil)
	if rec.Code != 400 || !strings.Contains(m["error"].(string), "key") {
		t.Fatalf("enable without key: %d %v", rec.Code, m)
	}

	// Pasting a config whose peer is in the catalog also selects that server.
	rec, m = do(t, h, "POST", "/api/key", confJSON(sampleConf), nil)
	if rec.Code != 200 {
		t.Fatalf("set key: %d %v", rec.Code, m)
	}
	if strings.Contains(rec.Body.String(), testKey) {
		t.Fatal("status response leaks the private key")
	}
	st := c.State()
	if st.Key == nil || st.Server == nil || st.Server.Name != "AF#1" {
		t.Fatalf("after key: key=%v server=%+v", st.Key, st.Server)
	}

	if rec, _ := do(t, h, "POST", "/api/state", `{"serverId":"203.0.113.99"}`, nil); rec.Code != 404 {
		t.Errorf("unknown server: %d, want 404", rec.Code)
	}

	var p2p controller.Server
	for _, s := range c.cat.All() {
		if s.P2P && s.CC == "CH" {
			p2p = s
			break
		}
	}
	rec, m = do(t, h, "POST", "/api/state", `{"serverId":"`+p2p.ID+`","enabled":true}`, nil)
	if rec.Code != 200 {
		t.Fatalf("connect: %d %v", rec.Code, m)
	}
	if st := c.State(); !st.Enabled || st.Server.ID != p2p.ID {
		t.Errorf("state after connect: enabled=%v server=%+v", st.Enabled, st.Server)
	}

	// Persisted, with the key, readable only by root.
	b, err := os.ReadFile(c.store.Path())
	if err != nil || !strings.Contains(string(b), p2p.ID) || !strings.Contains(string(b), testKey) {
		t.Errorf("state not persisted: %v", err)
	}

	// Removing the key also switches the VPN off.
	if rec, _ := do(t, h, "DELETE", "/api/key", "", nil); rec.Code != 200 {
		t.Errorf("delete key: %d", rec.Code)
	}
	if st := c.State(); st.Key != nil || st.Enabled {
		t.Errorf("after delete: key=%v enabled=%v", st.Key, st.Enabled)
	}
}

func TestAPIValidation(t *testing.T) {
	h, c := newTestAPI(t)
	for _, body := range []string{
		`{"pfTarget":"not-an-ip"}`,
		`{"pfTarget":"fd7a:115c:a1e0::1"}`,
		`{"pfTargetPort":70000}`,
		`{"pfTargetPort":-1}`,
		`{"killSwitch":"yes"}`,
		`not json`,
	} {
		if rec, _ := do(t, h, "POST", "/api/state", body, nil); rec.Code != 400 {
			t.Errorf("%s: %d, want 400", body, rec.Code)
		}
	}
	if rec, _ := do(t, h, "POST", "/api/key", confJSON("[Interface]\nPrivateKey = nope\n"), nil); rec.Code != 400 {
		t.Errorf("bad key: %d, want 400", rec.Code)
	}

	rec, _ := do(t, h, "POST", "/api/state", `{"pfTarget":" 100.64.1.2 ","pfTargetPort":8080,"killSwitch":false}`, nil)
	if rec.Code != 200 {
		t.Fatalf("valid settings: %d", rec.Code)
	}
	if st := c.State(); st.PFTarget != "100.64.1.2" || st.PFTargetPort != 8080 || st.KillSwitch {
		t.Errorf("settings not applied: %+v", st)
	}
	if rec, _ := do(t, h, "POST", "/api/state", `{"pfTarget":""}`, nil); rec.Code != 200 || c.State().PFTarget != "" {
		t.Error("clearing the forward target failed")
	}
}

func TestAPIServesDashboard(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, p := range []string{"/", "/map.js", "/flags/ch.svg"} {
		rec, _ := do(t, h, "GET", p, "", nil)
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("GET %s: %d (%d bytes)", p, rec.Code, rec.Body.Len())
		}
	}
	if rec, _ := do(t, h, "GET", "/flags/ch.svg", "", nil); !strings.Contains(rec.Header().Get("Cache-Control"), "max-age") {
		t.Error("static assets should be cacheable")
	}
	if rec, _ := do(t, h, "GET", "/", "", nil); rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
}

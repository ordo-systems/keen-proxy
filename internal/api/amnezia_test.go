package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestAmneziaImportPreview(t *testing.T) {
	s, d := newServer()
	before, _ := json.Marshal(d.cfg)
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	conf := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = never-resolve.invalid:51820\n"
	last, _ := json.Marshal(map[string]string{"config": conf})
	envelope, _ := json.Marshal(map[string]any{"format_version": 1, "hostName": "never-resolve.invalid", "userName": "ssh-user-secret", "password": "ssh-pass-secret", "containers": []any{map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": string(last)}}}})
	body, _ := json.Marshal(map[string]string{"uri": "vpn://" + base64.RawURLEncoding.EncodeToString(envelope)})
	h := s.Handler()
	if w := do(t, h, "POST", "/api/amnezia/import", string(body), "", lan); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	w := do(t, h, "POST", "/api/amnezia/import", string(body), "secret", lan)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d response=%s", w.Code, w.Body.String())
	}
	var result struct {
		Profiles []model.Connection `json:"profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 1 || result.Profiles[0].AmneziaWG != conf || result.Profiles[0].ID != "" {
		t.Fatal("incorrect preview candidate")
	}
	if strings.Contains(w.Body.String(), "ssh-") || strings.Contains(w.Body.String(), "vpn://") {
		t.Fatal("envelope leaked")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret response must not be cached")
	}
	after, _ := json.Marshal(d.cfg)
	if d.applied != nil || string(before) != string(after) {
		t.Fatal("preview modified daemon config")
	}
}

func TestAmneziaImportErrors(t *testing.T) {
	s, _ := newServer()
	for _, body := range []string{`{}`, `null`, `{"uri":7}`, `{"uri":"vpn://!!!"}`, `{"uri":"vpn://e30","extra":true}`, `{"uri":"vpn://e30"} {}`, `{"uri":"` + strings.Repeat("A", (2<<20)+1) + `"}`} {
		w := do(t, s.Handler(), "POST", "/api/amnezia/import", body, "secret", lan)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d", w.Code)
		}
		var response map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response["error"] != "amnezia_invalid_profile" {
			t.Fatalf("error=%s", response["error"])
		}
	}
}

func TestAmneziaImportStableClassificationErrors(t *testing.T) {
	for _, tc := range []struct{ payload, code string }{
		{`{"api_key":"service-secret","containers":[]}`, "amnezia_service_profile"},
		{`{"userName":"root","password":"ssh-secret"}`, "amnezia_admin_profile"},
		{`{"containers":[]}`, "amnezia_unsupported_profile"},
		{`{"format_version":2}`, "amnezia_format_version"},
	} {
		s, _ := newServer()
		body, _ := json.Marshal(map[string]string{"uri": "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(tc.payload))})
		w := do(t, s.Handler(), "POST", "/api/amnezia/import", string(body), "secret", lan)
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != `{"error":"`+tc.code+`"}` {
			t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
		}
	}
}

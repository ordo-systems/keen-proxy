package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/resourceexchange"
)

const (
	resourcePreviewPath = "/api/resources/preview"
	resourceExportPath  = "/api/resources/export"
)

func resourceRequest(path, contentType string, body io.Reader, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.RemoteAddr = lan
	r.Header.Set("Content-Type", contentType)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func resourceResponse[T any](t *testing.T, h http.Handler, r *http.Request, status int) T {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return decodeResourceResponse[T](t, w, status)
}

func decodeResourceResponse[T any](t *testing.T, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("response: %d %v %s", w.Code, w.Header(), w.Body)
	}
	var result T
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func resourceError(t *testing.T, h http.Handler, r *http.Request, status int) {
	t.Helper()
	if got := resourceResponse[map[string]string](t, h, r, status); got["error"] == "" {
		t.Fatalf("missing JSON error: %+v", got)
	}
}

type resourceUnreadBody struct{ read bool }

func (b *resourceUnreadBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func TestResourceExchangeAuth(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, tc := range []struct{ path, media string }{
		{resourcePreviewPath, "application/octet-stream"},
		{resourceExportPath, "application/json"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			body := &resourceUnreadBody{}
			resourceError(t, h, resourceRequest(tc.path+"?format=txt", tc.media, body, ""), http.StatusUnauthorized)
			if body.read {
				t.Fatal("unauthorized body was read")
			}
		})
	}
	r := resourceRequest(resourcePreviewPath+"?format=txt", "application/octet-stream", strings.NewReader("example.org"), "")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: s.Token})
	if got := resourceResponse[resourceexchange.Preview](t, h, r, http.StatusOK); !got.Valid {
		t.Fatalf("cookie-authenticated preview invalid: %+v", got)
	}
}

func TestResourceExchangeTransport(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, tc := range []struct {
		name, path, media, body string
		status                  int
	}{
		{"missing format", resourcePreviewPath, "application/octet-stream", "", http.StatusBadRequest},
		{"unknown format", resourceExportPath + "?format=xml", "application/json", "", http.StatusBadRequest},
		{"repeated format", resourcePreviewPath + "?format=txt&format=txt", "application/octet-stream", "", http.StatusBadRequest},
		{"extra parameter", resourceExportPath + "?format=txt&source=file", "application/json", "", http.StatusBadRequest},
		{"malformed query", resourcePreviewPath + "?format=txt&%xx", "application/octet-stream", "", http.StatusBadRequest},
		{"wrong preview media", resourcePreviewPath + "?format=txt", "text/plain", "", http.StatusUnsupportedMediaType},
		{"wrong export media", resourceExportPath + "?format=txt", "application/octet-stream", "", http.StatusUnsupportedMediaType},
		{"trailing object", resourceExportPath + "?format=txt", "application/json", `{"entries":[]} {}`, http.StatusBadRequest},
		{"trailing garbage", resourceExportPath + "?format=txt", "application/json", `{"entries":[]} junk`, http.StatusBadRequest},
		{"unknown field", resourceExportPath + "?format=txt", "application/json", `{"entries":[],"target":"direct"}`, http.StatusBadRequest},
		{"duplicate field", resourceExportPath + "?format=txt", "application/json", `{"entries":[],"entries":[]}`, http.StatusBadRequest},
		{"missing entries", resourceExportPath + "?format=txt", "application/json", `{"name":"example"}`, http.StatusBadRequest},
		{"null entries", resourceExportPath + "?format=txt", "application/json", `{"entries":null}`, http.StatusBadRequest},
		{"non-array entries", resourceExportPath + "?format=txt", "application/json", `{"entries":{}}`, http.StatusBadRequest},
		{"duplicate entry type", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"ip_cidr","type":"domain_suffix","value":"example.org"}]}`, http.StatusBadRequest},
		{"duplicate entry value", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"domain_suffix","value":"example.org","value":"another.example"}]}`, http.StatusBadRequest},
		{"duplicate entry activation", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"domain_suffix","value":"example.org","disabled":true,"disabled":false}]}`, http.StatusBadRequest},
		{"null entry activation", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"domain_suffix","value":"example.org","disabled":null}]}`, http.StatusBadRequest},
		{"string entry activation", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"domain_suffix","value":"example.org","disabled":"false"}]}`, http.StatusBadRequest},
		{"missing entry type", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"value":"example.org"}]}`, http.StatusBadRequest},
		{"wrong entry field case", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"Type":"domain_suffix","value":"example.org"}]}`, http.StatusBadRequest},
		{"unknown entry field", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"ip_cidr","value":"192.0.2.1","target":"direct"}]}`, http.StatusBadRequest},
		{"null list", resourceExportPath + "?format=txt", "application/json", `null`, http.StatusBadRequest},
		{"type mismatch", resourceExportPath + "?format=txt", "application/json", `{"entries":[{"type":"ip_cidr","value":"example.org"}]}`, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resourceError(t, h, resourceRequest(tc.path, tc.media, strings.NewReader(tc.body), s.Token), tc.status)
		})
	}

	req := resourceRequest(resourceExportPath+"?format=json", "application/json", strings.NewReader(`{"entries":[]}`), s.Token)
	got := resourceResponse[struct {
		Data []byte `json:"data"`
	}](t, h, req, http.StatusOK)
	preview := resourceexchange.Decode(resourceexchange.JSON, got.Data)
	if !preview.Valid || len(preview.List.Entries) != 0 {
		t.Fatalf("empty list export: %+v", preview)
	}
}

func TestResourceExchangeBodyLimit(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	path := resourcePreviewPath + "?format=txt"
	const octets = "application/octet-stream"
	exact := "#" + strings.Repeat(" ", resourceexchange.MaxFileBytes-1)
	if got := resourceResponse[resourceexchange.Preview](t, h, resourceRequest(path, octets, strings.NewReader(exact), s.Token), http.StatusOK); !got.Valid {
		t.Fatalf("preview at size limit failed: %+v", got)
	}

	// An unknown Content-Length exercises the actual MaxBytesReader limits.
	preview := io.MultiReader(strings.NewReader(exact), strings.NewReader(" "))
	resourceError(t, h, resourceRequest(path, octets, preview, s.Token), http.StatusRequestEntityTooLarge)
	// An otherwise valid JSON object is still oversized if trailing whitespace
	// takes it beyond the limit. Check that validation reads through EOF.
	export := io.MultiReader(strings.NewReader(`{"entries":[]}`), strings.NewReader(strings.Repeat(" ", maxResourceExportBytes)))
	exportPath := resourceExportPath + "?format=txt"
	resourceError(t, h, resourceRequest(exportPath, "application/json", export, s.Token), http.StatusRequestEntityTooLarge)

	const entry = `{"type":"ip_cidr","value":"192.0.2.1"}`
	entries := io.MultiReader(strings.NewReader(`{"entries":[`), strings.NewReader(strings.Repeat(entry+",", resourceexchange.MaxEntries)), strings.NewReader(entry+`]}`))
	resourceError(t, h, resourceRequest(exportPath, "application/json", entries, s.Token), http.StatusUnprocessableEntity)
}

func TestResourceExchangePreviewAndExportDoNotApply(t *testing.T) {
	s, d := newServer()
	d.cfg.Groups = []model.Group{{Name: "Saved group", Target: "direct", Entries: []string{"saved.example"}}}
	d.cfg.LocalPresets = []model.LocalPreset{{ID: "saved", Name: "Saved preset", Entries: []string{"saved.example"}}}
	h := s.Handler()
	before := do(t, h, http.MethodGet, "/api/config", "", s.Token, lan)
	if before.Code != http.StatusOK {
		t.Fatalf("initial configuration: %d %s", before.Code, before.Body)
	}

	previewPath := resourcePreviewPath + "?format=txt"
	valid := resourceResponse[resourceexchange.Preview](t, h, resourceRequest(previewPath, "application/octet-stream", strings.NewReader("*.Example.ORG.\n192.0.2.12\nexample.org\n"), s.Token), http.StatusOK)
	wantEntries := []resourceexchange.Entry{{Type: resourceexchange.DomainSuffix, Value: "example.org"}, {Type: resourceexchange.IPCIDR, Value: "192.0.2.12/32"}}
	if !valid.Valid || len(valid.Issues) != 0 || valid.Duplicates != 1 || !slices.Equal(valid.List.Entries, wantEntries) {
		t.Fatalf("valid preview: %+v", valid)
	}
	invalid := resourceResponse[resourceexchange.Preview](t, h, resourceRequest(previewPath, "application/octet-stream", strings.NewReader("example.org\ninvalid..example\n"), s.Token), http.StatusOK)
	if invalid.Valid || len(invalid.Issues) != 1 || invalid.Issues[0].Location != "line 2" {
		t.Fatalf("invalid preview: %+v", invalid)
	}

	body := `{"name":"Example","entries":[{"type":"domain_suffix","value":"EXAMPLE.ORG"},{"type":"ip_cidr","value":"192.0.2.12"},{"type":"domain_suffix","value":"omitted.example","disabled":true}]}`
	got := resourceResponse[struct {
		Data   string   `json:"data"`
		Losses []string `json:"losses"`
	}](t, h, resourceRequest(resourceExportPath+"?format=txt", "application/json; charset=utf-8", strings.NewReader(body), s.Token), http.StatusOK)
	wantLosses := []string{"The list name is not represented in this format.", "Disabled entries are omitted in this format."}
	if got.Data != base64.StdEncoding.EncodeToString([]byte("example.org\n192.0.2.12/32\n")) || !slices.Equal(got.Losses, wantLosses) {
		t.Fatalf("unexpected export: %+v", got)
	}

	after := do(t, h, http.MethodGet, "/api/config", "", s.Token, lan)
	if d.applied != nil || after.Code != http.StatusOK || !bytes.Equal(before.Body.Bytes(), after.Body.Bytes()) {
		t.Fatalf("exchange changed configuration: applied=%t; configuration status=%d", d.applied != nil, after.Code)
	}
}

func TestResourceExchangeDemoSRSRoundTrip(t *testing.T) {
	s, fake := newServer()
	s.D = &Demo{cfg: fake.cfg}
	h := s.Handler()
	input := `{"version":2,"rules":[{"domain_suffix":["example.org"],"ip_cidr":["192.0.2.0/25","192.0.2.128/25","2001:db8::/32"]}]}`
	source := resourceResponse[resourceexchange.Preview](t, h, resourceRequest(resourcePreviewPath+"?format=sing-box-json", "application/octet-stream", strings.NewReader(input), s.Token), http.StatusOK)
	if !source.Valid || len(source.List.Entries) != 4 {
		t.Fatalf("source preview: %+v", source)
	}
	list, err := json.Marshal(source.List)
	if err != nil {
		t.Fatal(err)
	}
	exported := resourceResponse[struct {
		Data   []byte   `json:"data"`
		Losses []string `json:"losses"`
	}](t, h, resourceRequest(resourceExportPath+"?format=srs", "application/json", bytes.NewReader(list), s.Token), http.StatusOK)
	if !bytes.HasPrefix(exported.Data, []byte("SRS")) || exported.Losses == nil || len(exported.Losses) != 0 {
		t.Fatalf("expected SRS bytes and empty losses array, got %d bytes and %#v", len(exported.Data), exported.Losses)
	}
	recovered := resourceResponse[resourceexchange.Preview](t, h, resourceRequest(resourcePreviewPath+"?format=srs", "application/octet-stream", bytes.NewReader(exported.Data), s.Token), http.StatusOK)
	entrySet := func(entries []resourceexchange.Entry) map[resourceexchange.Entry]int {
		set := make(map[resourceexchange.Entry]int, len(entries))
		for _, entry := range entries {
			set[entry]++
		}
		return set
	}
	if !recovered.Valid || !maps.Equal(entrySet(source.List.Entries), entrySet(recovered.List.Entries)) {
		t.Fatalf("SRS did not preserve suffix and CIDR entries: %+v", recovered)
	}
}

type resourcePausedReader struct {
	io.Reader
	started chan struct{}
	resume  <-chan struct{}
}

func (p *resourcePausedReader) Read(dst []byte) (int, error) {
	if p.started != nil {
		close(p.started)
		p.started = nil
		<-p.resume
	}
	return p.Reader.Read(dst)
}

func startResourceRequest(h http.Handler, r *http.Request) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	return done
}

func TestResourceExchangeSerializesBeforeReading(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	requests := [...]struct{ path, media, body string }{
		{resourcePreviewPath + "?format=txt", "application/octet-stream", "example.org"},
		{resourceExportPath + "?format=txt", "application/json", `{"entries":[]}`},
	}
	for i, active := range requests {
		t.Run(active.path, func(t *testing.T) {
			started, resume := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(resume) })
			t.Cleanup(unblock)
			body := &resourcePausedReader{Reader: strings.NewReader(active.body), started: started, resume: resume}
			first := resourceRequest(active.path, active.media, body, s.Token)
			done := startResourceRequest(h, first)
			select {
			case <-started:
			case w := <-done:
				t.Fatalf("active exchange returned before reading: %d %s", w.Code, w.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("active exchange did not begin reading")
			}

			other := requests[1-i]
			unread := &resourceUnreadBody{}
			competing := startResourceRequest(h, resourceRequest(other.path, other.media, unread, s.Token))
			select {
			case w := <-competing:
				got := decodeResourceResponse[map[string]string](t, w, http.StatusServiceUnavailable)
				if unread.read || got["error"] == "" || w.Header().Get("Connection") != "close" {
					t.Fatalf("busy exchange did not reject the competing body: read=%t; response=%v %s", unread.read, w.Header(), w.Body)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("competing exchange waited for the gate instead of being rejected")
			}
			unblock()
			select {
			case w := <-done:
				decodeResourceResponse[json.RawMessage](t, w, http.StatusOK)
			case <-time.After(5 * time.Second):
				t.Fatal("active exchange did not finish")
			}
			resourceResponse[json.RawMessage](t, h, resourceRequest(other.path, other.media, strings.NewReader(other.body), s.Token), http.StatusOK)
		})
	}
}

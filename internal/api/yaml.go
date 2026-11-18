package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Bound input before YAML allocates its document tree. Raw transport still
// leaves room for a large local preset copied into a routing group.
const maxYAMLImportBytes = 3 << 20

// decodeFeatureRequest accepts one JSON value up to 2 MiB and rejects unknown fields.
func decodeFeatureRequest(w http.ResponseWriter, r *http.Request, v any) error {
	return decodeJSONRequest(w, r, 2<<20, v)
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// yamlExport serves a restorable backup or an explicitly non-restorable redacted support file.
func (s *Server) yamlExport(w http.ResponseWriter, r *http.Request) {
	c := s.D.Config()
	raw, err := c.Marshal()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	name := "keenproxy-backup.yaml"
	if r.URL.Query().Get("redacted") == "1" {
		// An intentionally non-restorable support file. Clear entire connection
		// profiles, including AmneziaWG text, instead of guessing secret field names.
		cp := c.Clone()
		cp.LocalPresets = nil
		cp.DNS.Upstreams = []string{"REDACTED"}
		cp.DNS.BypassSources = nil
		for i := range cp.GeoIP.Databases {
			if cp.GeoIP.Databases[i].URL != "" {
				cp.GeoIP.Databases[i].URL = "REDACTED"
			}
		}
		cp.Failover.URL = "REDACTED"
		for i := range cp.Filters.Sources {
			cp.Filters.Sources[i].URL = "REDACTED"
		}
		for i := range cp.Connections {
			cn := &cp.Connections[i]
			cn.Link = "REDACTED"
			cn.WireGuard = nil
			cn.Outbound = nil
			cn.Endpoint = nil
			cn.TrustTunnel = nil
			cn.AmneziaWG = ""
		}
		for i := range cp.Groups {
			cp.Groups[i].DisabledEntries = nil
		}
		raw, err = cp.Marshal()
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		raw = append([]byte("# SUPPORT ONLY — secrets removed; not a restorable backup\nredacted: true\n"), raw...)
		name = "keenproxy-support-redacted.yaml"
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(raw)
}

// previousConfig returns the optional prior configuration as an uncached draft candidate.
// It never restores or applies the returned configuration.
func (s *Server) previousConfig(w http.ResponseWriter, r *http.Request) {
	d, ok := s.D.(interface{ PreviousConfig() (*model.Config, error) })
	if !ok {
		writeError(w, 404, "Previous file is unavailable in demo")
		return
	}
	c, err := d.PreviousConfig()
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, c)
}

// yamlImport parses and validates YAML for preview without applying it.
func (s *Server) yamlImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.resourceBusy.CompareAndSwap(false, true) {
		rejectResourceRequest(w, r, http.StatusServiceUnavailable, "another file conversion is in progress")
		return
	}
	defer s.resourceBusy.Store(false)
	setFileConversionDeadlines(w)

	var raw []byte
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType == "application/yaml" {
		const tooLarge = "YAML configuration exceeds 3 MiB"
		if r.ContentLength > maxYAMLImportBytes {
			rejectResourceRequest(w, r, http.StatusRequestEntityTooLarge, tooLarge)
			return
		}
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxYAMLImportBytes))
		if err != nil {
			var limit *http.MaxBytesError
			if errors.As(err, &limit) {
				writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
			} else {
				writeError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
	} else {
		// Preserve the small JSON wrapper for existing clients. The panel sends
		// YAML directly so JSON escape expansion does not consume its budget.
		var req struct {
			YAML string `json:"yaml"`
		}
		if err := decodeFeatureRequest(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		raw = []byte(req.YAML)
	}
	c, err := model.Parse(raw)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

package api

import (
	"net/http"

	"github.com/ordo-systems/keen-proxy/internal/amnezia"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// amneziaImport only decodes a standalone export into draft candidates. It does
// not resolve names, modify DNS, call Amnezia services or apply configuration.
func (s *Server) amneziaImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		URI string `json:"uri"`
	}
	if err := decodeFeatureRequest(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, amnezia.ErrInvalidProfile.Error())
		return
	}
	profiles, err := amnezia.Import(req.URI)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Profiles []model.Connection `json:"profiles"`
	}{Profiles: profiles})
}

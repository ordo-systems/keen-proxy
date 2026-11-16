// Package amnezia decodes standalone Amnezia vpn:// exports without network access.
// Schema baseline: amnezia-client 1efeab81b6ff384f6fbf7679428ebef551adeda1,
// configKeys.h, apiKeys.h, serverConfigUtils.h and AwgProtocolConfig.
package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

const (
	MaxDecodedSize = 1 << 20
	MaxURISize     = 2 << 20
)

// MaxAWGCandidates is the maximum number of AmneziaWG containers constructed
// from one export. The next candidate is rejected before it is built, and the
// export is not partially imported.
const MaxAWGCandidates = 32

// MaxAggregateProfileBytes is the maximum cumulative native profile text
// retained from one export. Structured fields such as root DNS are still
// copied into each profile; a candidate that would exceed this total is not
// retained, and the export is rejected as a whole.
const MaxAggregateProfileBytes = 1 << 20

var (
	ErrInvalidProfile     = errors.New("amnezia_invalid_profile")
	ErrServiceProfile     = errors.New("amnezia_service_profile")
	ErrAdminProfile       = errors.New("amnezia_admin_profile")
	ErrUnsupportedProfile = errors.New("amnezia_unsupported_profile")
	ErrFormatVersion      = errors.New("amnezia_format_version")
)

type object map[string]json.RawMessage

// Import returns preview-only connections. Neither envelope metadata nor service
// or SSH credentials are copied into the canonical connection model.
func Import(uri string) ([]model.Connection, error) {
	raw, err := decodeURI(uri)
	if err != nil {
		return nil, err
	}
	root, err := parseObject(raw)
	if err != nil {
		return nil, err
	}
	if err := classify(root); err != nil {
		return nil, err
	}
	return extract(root)
}

func decodeURI(uri string) ([]byte, error) {
	if len(uri) > MaxURISize {
		return nil, ErrInvalidProfile
	}
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, "vpn://") {
		return nil, ErrInvalidProfile
	}
	raw, err := decodePayload(strings.TrimPrefix(uri, "vpn://"))
	if err != nil || len(raw) == 0 {
		return nil, ErrInvalidProfile
	}
	return decodeBody(raw)
}

func decodePayload(encoded string) ([]byte, error) {
	enc := base64.RawURLEncoding.Strict()
	if strings.HasSuffix(encoded, "=") {
		enc = base64.URLEncoding.Strict()
	}
	return enc.DecodeString(encoded)
}

func decodeBody(raw []byte) ([]byte, error) {
	if isJSONBody(bytes.TrimSpace(raw)) {
		if len(raw) > MaxDecodedSize {
			return nil, ErrInvalidProfile
		}
		return raw, nil
	}
	return uncompress(raw)
}

func isJSONBody(trimmed []byte) bool {
	return bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("[")) || bytes.Equal(trimmed, []byte("null"))
}

func uncompress(raw []byte) ([]byte, error) {
	if len(raw) < 5 {
		return nil, ErrInvalidProfile
	}
	declared := binary.BigEndian.Uint32(raw[:4])
	if declared > MaxDecodedSize {
		return nil, ErrInvalidProfile
	}
	input := bytes.NewReader(raw[4:])
	r, err := zlib.NewReader(input)
	if err != nil {
		return nil, ErrInvalidProfile
	}
	defer r.Close()
	decoded, err := io.ReadAll(io.LimitReader(r, MaxDecodedSize+1))
	if err != nil || len(decoded) > MaxDecodedSize || input.Len() != 0 {
		return nil, ErrInvalidProfile
	}
	if uint32(len(decoded)) != declared {
		return nil, compressedSizeError(decoded, declared)
	}
	return decoded, nil
}

// Premium service links use 0x000000ff as a signature instead of a length.
// Recognize that envelope only to reject it; standalone length checks stay strict.
func compressedSizeError(decoded []byte, declared uint32) error {
	if declared == 255 {
		root, err := parseObject(decoded)
		if err == nil && errors.Is(classify(root), ErrServiceProfile) {
			return ErrServiceProfile
		}
	}
	return ErrInvalidProfile
}

func parseObject(raw []byte) (object, error) {
	var obj object
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, ErrInvalidProfile
	}
	return obj, nil
}

func classify(root object) error {
	// Presence, not truthiness, fails closed for cached subscription exports too.
	for _, key := range []string{"config_version", "api_config", "api_key", "auth_data", "api_endpoint", "service_type", "service_info", "service_protocol", "vpn_key", "api_payload", "key_payload"} {
		if _, ok := root[key]; ok {
			return ErrServiceProfile
		}
	}
	if raw, ok := root["format_version"]; ok {
		var version int
		if err := json.Unmarshal(raw, &version); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || version < 0 || version > 1 {
			return ErrFormatVersion
		}
	}
	return nil
}

func extract(root object) ([]model.Connection, error) {
	var containers []object
	if raw, ok := root["containers"]; ok {
		if err := json.Unmarshal(raw, &containers); err != nil {
			return nil, ErrInvalidProfile
		}
	}
	profiles, err := collectAWGProfiles(root, containers)
	if err != nil {
		return nil, err
	}
	if len(profiles) != 0 {
		return profiles, nil
	}
	if hasAdminCredentials(root) {
		return nil, ErrAdminProfile
	}
	return nil, ErrUnsupportedProfile
}

// collectAWGProfiles bounds retained candidates before any preview is returned.
// The slice length is the candidate count; failed exports never return a prefix.
func collectAWGProfiles(root object, containers []object) ([]model.Connection, error) {
	profiles := make([]model.Connection, 0, min(len(containers), MaxAWGCandidates))
	remaining := MaxAggregateProfileBytes
	for _, container := range containers {
		kind := text(container, "container")
		if kind != "amnezia-awg" && kind != "amnezia-awg2" {
			continue
		}
		if len(profiles) >= MaxAWGCandidates {
			return nil, ErrInvalidProfile
		}
		profile, err := containerProfile(root, container)
		if err != nil {
			return nil, err
		}
		if len(profile) > remaining {
			return nil, ErrInvalidProfile
		}
		remaining -= len(profile)
		profiles = append(profiles, model.Connection{Name: fmt.Sprintf("AmneziaWG (%s, %d)", kind, len(profiles)+1), Type: "amneziawg", AmneziaWG: profile})
	}
	return profiles, nil
}

func hasAdminCredentials(root object) bool {
	return text(root, "userName") != "" || text(root, "password") != ""
}

func containerProfile(root, container object) (string, error) {
	server, client, err := openClient(root, container)
	if err != nil {
		return "", err
	}
	return renderProfile(root, server, client)
}

func openClient(root, container object) (object, object, error) {
	server, err := parseObject(container["awg"])
	if err != nil {
		return nil, nil, err
	}
	last := server["last_config"]
	if len(last) == 0 || bytes.Equal(last, []byte("null")) {
		if hasAdminCredentials(root) {
			return nil, nil, ErrAdminProfile
		}
		return nil, nil, ErrInvalidProfile
	}
	var encoded string
	if json.Unmarshal(last, &encoded) == nil {
		last = []byte(encoded)
	}
	client, err := parseObject(last)
	if err != nil {
		return nil, nil, err
	}
	if err := validateClientFields(client); err != nil {
		return nil, nil, err
	}
	return server, client, nil
}

func renderProfile(root, server, client object) (string, error) {
	config := text(client, "config")
	var err error
	if config == "" {
		config, err = structuredConfig(root, server, client)
	} else {
		err = validateNativeOptions(config, client)
	}
	if err != nil {
		return "", err
	}
	if _, err := awg.Parse(config); err != nil {
		return "", ErrUnsupportedProfile
	}
	return config, nil
}

func text(obj object, key string) string {
	var value string
	_ = json.Unmarshal(obj[key], &value)
	return value
}

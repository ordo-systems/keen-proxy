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
	encoded := strings.TrimPrefix(uri, "vpn://")
	enc := base64.RawURLEncoding.Strict()
	if strings.HasSuffix(encoded, "=") {
		enc = base64.URLEncoding.Strict()
	}
	raw, err := enc.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return nil, ErrInvalidProfile
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if len(raw) > MaxDecodedSize {
			return nil, ErrInvalidProfile
		}
		return raw, nil
	}
	return uncompress(raw)
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
	var profiles []model.Connection
	for _, container := range containers {
		kind := text(container, "container")
		if kind != "amnezia-awg" && kind != "amnezia-awg2" {
			continue
		}
		profile, err := containerProfile(root, container)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, model.Connection{Name: fmt.Sprintf("AmneziaWG (%s, %d)", kind, len(profiles)+1), Type: "amneziawg", AmneziaWG: profile})
	}
	if len(profiles) != 0 {
		return profiles, nil
	}
	if hasAdminCredentials(root) {
		return nil, ErrAdminProfile
	}
	return nil, ErrUnsupportedProfile
}

func hasAdminCredentials(root object) bool {
	return text(root, "userName") != "" || text(root, "password") != ""
}

func containerProfile(root, container object) (string, error) {
	server, err := parseObject(container["awg"])
	if err != nil {
		return "", err
	}
	last := server["last_config"]
	if len(last) == 0 || bytes.Equal(last, []byte("null")) {
		if hasAdminCredentials(root) {
			return "", ErrAdminProfile
		}
		return "", ErrInvalidProfile
	}
	var encoded string
	if json.Unmarshal(last, &encoded) == nil {
		last = []byte(encoded)
	}
	client, err := parseObject(last)
	if err != nil {
		return "", err
	}
	if err := validateClientFields(client); err != nil {
		return "", err
	}
	config := text(client, "config")
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

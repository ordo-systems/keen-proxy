package links

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// xhttpSpec describes one Xray share-link field and the sing-box transport key
// it becomes. Names follow SPECS/TASKS/002-XHTTP_CLIENT_TRANSPORT/URL_PARSING.md
// and option.V2RayXHTTPOptions.
type xhttpSpec struct {
	json string
	kind string
	enum []string
	fold bool
}

var xhttpSpecs = map[string]xhttpSpec{
	"host":                     {json: "host", kind: "string"},
	"path":                     {json: "path", kind: "string"},
	"mode":                     {json: "mode", kind: "enum", enum: []string{"auto", "packet-up", "stream-up", "stream-one"}, fold: true},
	"xPaddingBytes":            {json: "x_padding_bytes", kind: "range"},
	"x_padding_bytes":          {json: "x_padding_bytes", kind: "range"},
	"noGRPCHeader":             {json: "no_grpc_header", kind: "bool"},
	"no_grpc_header":           {json: "no_grpc_header", kind: "bool"},
	"sessionPlacement":         {json: "session_placement", kind: "enum", enum: []string{"path", "query", "header", "cookie"}},
	"session_placement":        {json: "session_placement", kind: "enum", enum: []string{"path", "query", "header", "cookie"}},
	"sessionKey":               {json: "session_key", kind: "string"},
	"session_key":              {json: "session_key", kind: "string"},
	"seqPlacement":             {json: "seq_placement", kind: "enum", enum: []string{"path", "query", "header", "cookie"}},
	"seq_placement":            {json: "seq_placement", kind: "enum", enum: []string{"path", "query", "header", "cookie"}},
	"seqKey":                   {json: "seq_key", kind: "string"},
	"seq_key":                  {json: "seq_key", kind: "string"},
	"sessionTable":             {json: "session_table", kind: "string"},
	"session_table":            {json: "session_table", kind: "string"},
	"sessionLength":            {json: "session_length", kind: "range"},
	"session_length":           {json: "session_length", kind: "range"},
	"uplinkDataPlacement":      {json: "uplink_data_placement", kind: "enum", enum: []string{"body", "auto", "header", "cookie"}},
	"uplink_data_placement":    {json: "uplink_data_placement", kind: "enum", enum: []string{"body", "auto", "header", "cookie"}},
	"uplinkDataKey":            {json: "uplink_data_key", kind: "string"},
	"uplink_data_key":          {json: "uplink_data_key", kind: "string"},
	"uplinkChunkSize":          {json: "uplink_chunk_size", kind: "range"},
	"uplink_chunk_size":        {json: "uplink_chunk_size", kind: "range"},
	"uplinkHTTPMethod":         {json: "uplink_http_method", kind: "method"},
	"uplink_http_method":       {json: "uplink_http_method", kind: "method"},
	"xPaddingObfsMode":         {json: "x_padding_obfs_mode", kind: "bool"},
	"x_padding_obfs_mode":      {json: "x_padding_obfs_mode", kind: "bool"},
	"xPaddingKey":              {json: "x_padding_key", kind: "string"},
	"x_padding_key":            {json: "x_padding_key", kind: "string"},
	"xPaddingHeader":           {json: "x_padding_header", kind: "string"},
	"x_padding_header":         {json: "x_padding_header", kind: "string"},
	"xPaddingPlacement":        {json: "x_padding_placement", kind: "enum", enum: []string{"cookie", "header", "query", "queryInHeader"}},
	"x_padding_placement":      {json: "x_padding_placement", kind: "enum", enum: []string{"cookie", "header", "query", "queryInHeader"}},
	"xPaddingMethod":           {json: "x_padding_method", kind: "enum", enum: []string{"repeat-x", "tokenish"}},
	"x_padding_method":         {json: "x_padding_method", kind: "enum", enum: []string{"repeat-x", "tokenish"}},
	"scMaxEachPostBytes":       {json: "sc_max_each_post_bytes", kind: "range"},
	"sc_max_each_post_bytes":   {json: "sc_max_each_post_bytes", kind: "range"},
	"scMinPostsIntervalMs":     {json: "sc_min_posts_interval_ms", kind: "range"},
	"sc_min_posts_interval_ms": {json: "sc_min_posts_interval_ms", kind: "range"},
}

// Server-only and legacy knobs are accepted so a symmetric link still imports.
// They do not change the client. See protocols-transports.md §1.8.
var xhttpIgnored = map[string]bool{
	"scMaxConcurrentPosts":     true,
	"sc_max_concurrent_posts":  true,
	"serverMaxHeaderBytes":     true,
	"server_max_header_bytes":  true,
	"noSSEHeader":              true,
	"no_sse_header":            true,
	"scMaxBufferedPosts":       true,
	"sc_max_buffered_posts":    true,
	"scStreamUpServerSecs":     true,
	"sc_stream_up_server_secs": true,
}

// These change the connection and have no sing-box field. Dropping them would
// import a different tunnel.
var xhttpRejected = map[string]bool{
	"downloadSettings":  true,
	"download_settings": true,
	"quicParams":        true,
	"quic_params":       true,
}

var xmuxSpecs = map[string]xhttpSpec{
	"maxConcurrency":      {json: "max_concurrency", kind: "range"},
	"max_concurrency":     {json: "max_concurrency", kind: "range"},
	"maxConnections":      {json: "max_connections", kind: "range"},
	"max_connections":     {json: "max_connections", kind: "range"},
	"cMaxReuseTimes":      {json: "c_max_reuse_times", kind: "range"},
	"c_max_reuse_times":   {json: "c_max_reuse_times", kind: "range"},
	"hMaxRequestTimes":    {json: "h_max_request_times", kind: "range"},
	"h_max_request_times": {json: "h_max_request_times", kind: "range"},
	"hMaxReusableSecs":    {json: "h_max_reusable_secs", kind: "range"},
	"h_max_reusable_secs": {json: "h_max_reusable_secs", kind: "range"},
	"hKeepAlivePeriod":    {json: "h_keep_alive_period", kind: "int"},
	"h_keep_alive_period": {json: "h_keep_alive_period", kind: "int"},
}

// xhttpTransport maps type=xhttp and type=splithttp, including extra JSON and xmux.
// The path is kept whole, query tail included: relays read parameters from it.
func xhttpTransport(q url.Values) (map[string]any, error) {
	for _, name := range []string{"downloadSettings", "download_settings", "quicParams", "quic_params"} {
		if q.Has(name) {
			return nil, fmt.Errorf("xhttp: unsupported option %q", name)
		}
	}
	fields := map[string]any{}
	if err := applyXHTTPQuery(fields, q); err != nil {
		return nil, err
	}
	if raw := strings.TrimSpace(q.Get("extra")); raw != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return nil, fmt.Errorf("xhttp: extra must be a JSON object")
		}
		if err := applyXHTTPObject(fields, extra); err != nil {
			return nil, err
		}
	}
	fields["type"] = "xhttp"
	return fields, nil
}

func applyXHTTPQuery(dst map[string]any, q url.Values) error {
	seen := map[string]string{}
	for name, spec := range xhttpSpecs {
		if !q.Has(name) {
			continue
		}
		if prev, ok := seen[spec.json]; ok && prev != q.Get(name) {
			return fmt.Errorf("xhttp: conflicting values for %s", spec.json)
		}
		seen[spec.json] = q.Get(name)
		if err := applyXHTTPValue(dst, spec, q.Get(name)); err != nil {
			return err
		}
	}
	return nil
}

func applyXHTTPObject(dst map[string]any, obj map[string]any) error {
	seen := make(map[string]struct{}, len(obj))
	for name, val := range obj {
		if xhttpIgnored[name] {
			continue
		}
		if xhttpRejected[name] {
			return fmt.Errorf("xhttp: unsupported option %q", name)
		}
		switch name {
		case "xmux":
			if err := applyXmux(dst, val); err != nil {
				return err
			}
			continue
		case "headers":
			headers, err := headerObject(val)
			if err != nil {
				return err
			}
			if headers == nil {
				delete(dst, "headers")
				continue
			}
			dst["headers"] = headers
			continue
		}
		spec, ok := xhttpSpecs[name]
		if !ok {
			return fmt.Errorf("xhttp: unsupported option %q", name)
		}
		if _, duplicate := seen[spec.json]; duplicate {
			return fmt.Errorf("xhttp: conflicting values for %s", spec.json)
		}
		seen[spec.json] = struct{}{}
		if err := applyXHTTPValue(dst, spec, val); err != nil {
			return err
		}
	}
	return nil
}

func applyXHTTPValue(dst map[string]any, spec xhttpSpec, val any) error {
	if val == nil {
		delete(dst, spec.json)
		return nil
	}
	parsed, omit, err := parseXHTTPValue(spec, val)
	if err != nil {
		return err
	}
	if omit {
		delete(dst, spec.json)
		return nil
	}
	dst[spec.json] = parsed
	return nil
}

func parseXHTTPValue(spec xhttpSpec, val any) (any, bool, error) {
	switch spec.kind {
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, false, fmt.Errorf("xhttp: %s must be a string", spec.json)
		}
		s = strings.TrimSpace(s)
		return s, s == "", nil
	case "method":
		s, ok := val.(string)
		if !ok {
			return nil, false, fmt.Errorf("xhttp: %s must be a string", spec.json)
		}
		s = strings.ToUpper(strings.TrimSpace(s))
		return s, s == "", nil
	case "enum":
		s, ok := val.(string)
		if !ok {
			return nil, false, fmt.Errorf("xhttp: %s must be a string", spec.json)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return "", true, nil
		}
		got := s
		if spec.fold {
			got = strings.ToLower(s)
		}
		for _, allowed := range spec.enum {
			if got == allowed {
				return allowed, false, nil
			}
		}
		return nil, false, fmt.Errorf("xhttp: %s %q is not supported", spec.json, s)
	case "bool":
		b, err := boolValue(val)
		if err != nil {
			return nil, false, fmt.Errorf("xhttp: %s: %w", spec.json, err)
		}
		return b, false, nil
	case "range":
		s, err := rangeValue(val)
		if err != nil {
			return nil, false, fmt.Errorf("xhttp: %s: %w", spec.json, err)
		}
		return s, s == "", nil
	case "int":
		n, err := intValue(val)
		if err != nil {
			return nil, false, fmt.Errorf("xhttp: %s: %w", spec.json, err)
		}
		return n, false, nil
	default:
		return nil, false, fmt.Errorf("xhttp: unknown field kind %s", spec.kind)
	}
}

func applyXmux(dst map[string]any, val any) error {
	if val == nil {
		delete(dst, "xmux")
		return nil
	}
	obj, ok := val.(map[string]any)
	if !ok {
		return fmt.Errorf("xhttp: xmux must be an object")
	}
	mapped := map[string]any{}
	seen := map[string]struct{}{}
	for name, item := range obj {
		spec, ok := xmuxSpecs[name]
		if !ok {
			return fmt.Errorf("xhttp: unsupported xmux option %q", name)
		}
		if _, dup := seen[spec.json]; dup {
			return fmt.Errorf("xhttp: conflicting values for xmux.%s", spec.json)
		}
		seen[spec.json] = struct{}{}
		if err := applyXHTTPValue(mapped, spec, item); err != nil {
			return err
		}
	}
	if len(mapped) == 0 {
		delete(dst, "xmux")
		return nil
	}
	dst["xmux"] = mapped
	return nil
}

func headerObject(val any) (map[string]any, error) {
	if val == nil {
		return nil, nil
	}
	obj, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("xhttp: headers must be an object")
	}
	out := make(map[string]any, len(obj))
	for name, item := range obj {
		switch x := item.(type) {
		case string:
			out[name] = x
		case []any:
			list := make([]string, len(x))
			for i, v := range x {
				s, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("xhttp: header %s values must be strings", name)
				}
				list[i] = s
			}
			out[name] = list
		default:
			return nil, fmt.Errorf("xhttp: header %s values must be strings", name)
		}
	}
	return out, nil
}

func boolValue(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		return parseBool(x)
	case float64:
		if x == 1 {
			return true, nil
		}
		if x == 0 {
			return false, nil
		}
	}
	return false, fmt.Errorf("invalid boolean %v", v)
}

func rangeValue(v any) (string, error) {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return "", nil
		}
		if err := validRangeString(s); err != nil {
			return "", err
		}
		return s, nil
	case float64:
		return formatInt(x)
	case []any:
		if len(x) < 1 || len(x) > 2 {
			return "", fmt.Errorf("range array takes 1 or 2 elements")
		}
		parts := make([]string, len(x))
		for i, item := range x {
			n, ok := item.(float64)
			if !ok {
				return "", fmt.Errorf("range array values must be integers")
			}
			s, err := formatInt(n)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		if len(parts) == 1 {
			return parts[0], nil
		}
		return parts[0] + "-" + parts[1], nil
	default:
		return "", fmt.Errorf("invalid range %v", v)
	}
}

func validRangeString(s string) error {
	if !strings.Contains(s, "-") {
		if _, err := strconv.Atoi(s); err != nil {
			return fmt.Errorf("invalid range %q", s)
		}
		return nil
	}
	parts := strings.SplitN(s, "-", 2)
	if _, err := strconv.Atoi(strings.TrimSpace(parts[0])); err != nil {
		return fmt.Errorf("invalid range %q", s)
	}
	if _, err := strconv.Atoi(strings.TrimSpace(parts[1])); err != nil {
		return fmt.Errorf("invalid range %q", s)
	}
	return nil
}

func intValue(v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		s, err := formatInt(x)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(s, 10, 64)
	case string:
		return strconv.ParseInt(strings.TrimSpace(x), 10, 64)
	default:
		return 0, fmt.Errorf("invalid integer %v", v)
	}
}

func formatInt(n float64) (string, error) {
	if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
		return "", fmt.Errorf("expected an integer, got %v", n)
	}
	if n > math.MaxInt64 || n < math.MinInt64 {
		return "", fmt.Errorf("integer out of range")
	}
	return strconv.FormatInt(int64(n), 10), nil
}

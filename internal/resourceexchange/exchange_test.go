package resourceexchange

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestExchangeNormalizedRoundTrip(t *testing.T) {
	cases := []struct {
		format Format
		source string
		want   List
	}{
		{Text, "\ufeff # first line\r\n\r\n*.Example.COM. # suffix\r\n192.0.2.5/24\n2001:db8::1\n", List{Entries: []Entry{
			{Type: DomainSuffix, Value: "example.com"}, {Type: IPCIDR, Value: "192.0.2.0/24"}, {Type: IPCIDR, Value: "2001:db8::1/128"},
		}}},
		{CSV, "\ufeff\"type\",\"value\"\r\n\"domain_suffix\",\".Example.COM\"\r\nip_cidr,192.0.2.5\r\n", List{Entries: []Entry{
			{Type: DomainSuffix, Value: "example.com"}, {Type: IPCIDR, Value: "192.0.2.5/32"},
		}}},
		{JSON, "\ufeff" + `{"version":1,"name":"Example <list>","entries":[{"value":"2001:db8::1/64","disabled":true,"type":"ip_cidr"},{"type":"domain_suffix","value":"\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"}]}`, List{Name: "Example <list>", Entries: []Entry{
			{Type: IPCIDR, Value: "2001:db8::/64", Disabled: true}, {Type: DomainSuffix, Value: "xn--e1afmkfd.xn--p1ai"},
		}}},
		{Text, "*.RU\n", List{Entries: []Entry{{Type: DomainSuffix, Value: "ru"}}}},
		{CSV, "type,value\ndomain_suffix,.RU\n", List{Entries: []Entry{{Type: DomainSuffix, Value: "ru"}}}},
		{JSON, `{"version":1,"entries":[{"type":"domain_suffix","value":"ru","disabled":true}]}`, List{Entries: []Entry{{Type: DomainSuffix, Value: "ru", Disabled: true}}}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			preview := Decode(tc.format, []byte(tc.source))
			assertExchangeList(t, preview, tc.want)
			data, losses, err := Encode(tc.format, preview.List)
			if err != nil || len(losses) != 0 {
				t.Fatalf("encode: losses %v, error %v", losses, err)
			}
			assertExchangeList(t, Decode(tc.format, data), tc.want)
		})
	}
}

func assertExchangeList(t *testing.T, preview Preview, want List) {
	t.Helper()
	if !preview.Valid || len(preview.Issues) != 0 || preview.List.Name != want.Name || !slices.Equal(preview.List.Entries, want.Entries) {
		t.Fatalf("got %+v, want valid list %+v", preview, want)
	}
}

func TestExchangeEmptyLists(t *testing.T) {
	for _, tc := range []struct {
		format Format
		data   string
	}{
		{Text, ""},
		{Text, "\ufeff# comment\r\n  \n"},
		{CSV, "type,value\n"},
		{JSON, `{"version":1,"entries":[]}`},
	} {
		preview := Decode(tc.format, []byte(tc.data))
		assertExchangeList(t, preview, List{})
		if preview.List.Entries == nil || preview.Issues == nil {
			t.Fatalf("empty %s preview must carry arrays: %+v", tc.format, preview)
		}
		data, losses, err := Encode(tc.format, List{})
		if err != nil || len(losses) != 0 {
			t.Fatalf("encode empty %s: losses %v, error %v", tc.format, losses, err)
		}
		assertExchangeList(t, Decode(tc.format, data), List{})
	}
}

func TestExchangeStrictInput(t *testing.T) {
	cases := []struct {
		name     string
		format   Format
		data     string
		location string
	}{
		{"format", "other", "example.com", "file"},
		{"invalid UTF-8", Text, "\xff", "file"},
		{"invalid domain labels", Text, "ok.example\ninvalid..example", "line 2"},
		{"invalid wildcard", Text, "*example.com", "line 1"},
		{"TXT wildcard normalizes to IP", Text, "*.192.0.2.1", "line 1"},
		{"TXT dotted suffix normalizes to IP", Text, ".192.0.2.1.", "line 1"},
		{"TXT IDNA suffix normalizes to IP", Text, "１９２。０。２。１", "line 1"},
		{"zoned address", Text, "fe80::1%eth0", "line 1"},
		{"CSV empty file", CSV, "", "line 1"},
		{"CSV unknown header", CSV, "value,type\n", "line 1"},
		{"CSV extra column", CSV, "type,value\nip_cidr,192.0.2.1,true\n", "line 2"},
		{"CSV malformed quoting", CSV, "type,value\n\"domain_suffix,example.com\n", "line 2"},
		{"CSV mismatch", CSV, "type,value\nip_cidr,example.com\n", "line 2"},
		{"CSV suffix normalizes to IP", CSV, "type,value\ndomain_suffix,*.192.0.2.1\n", "line 2"},
		{"CSV comment in value", CSV, "type,value\ndomain_suffix,\"example.com # not a comment\"\n", "line 2"},
		{"JSON unknown version", JSON, `{"version":2,"entries":[]}`, "file"},
		{"JSON missing version", JSON, `{"entries":[]}`, "file"},
		{"JSON missing entries", JSON, `{"version":1}`, "file"},
		{"JSON null entries", JSON, `{"version":1,"entries":null}`, "entries"},
		{"JSON null name", JSON, `{"version":1,"name":null,"entries":[]}`, "file"},
		{"JSON duplicate top field", JSON, `{"version":1,"entries":[],"entries":[]}`, "file"},
		{"JSON unknown top field", JSON, `{"version":1,"Entries":[]}`, "file"},
		{"JSON trailing data", JSON, `{"version":1,"entries":[]} {}`, "file"},
		{"JSON null entry", JSON, `{"version":1,"entries":[null]}`, "entries[0]"},
		{"JSON missing type", JSON, `{"version":1,"entries":[{"value":"example.test"}]}`, "entries[0]"},
		{"JSON missing value", JSON, `{"version":1,"entries":[{"type":"domain_suffix"}]}`, "entries[0]"},
		{"JSON unknown entry field", JSON, `{"version":1,"entries":[{"type":"domain_suffix","value":"example.test","target":"proxy"}]}`, "entries[0]"},
		{"JSON duplicate entry field", JSON, `{"version":1,"entries":[{"type":"domain_suffix","type":"ip_cidr","value":"192.0.2.1"}]}`, "entries[0]"},
		{"JSON null activation", JSON, `{"version":1,"entries":[{"type":"domain_suffix","value":"example.test","disabled":null}]}`, "entries[0]"},
		{"JSON mismatch", JSON, `{"version":1,"entries":[{"type":"domain_suffix","value":"192.0.2.1"}]}`, "entries[0]"},
		{"JSON suffix normalizes to IP", JSON, `{"version":1,"entries":[{"type":"domain_suffix","value":"*.192.0.2.1"}]}`, "entries[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preview := Decode(tc.format, []byte(tc.data))
			if preview.Valid || len(preview.Issues) != 1 || preview.Issues[0].Kind != "error" || preview.Issues[0].Location != tc.location {
				t.Fatalf("got %+v, want error at %q", preview, tc.location)
			}
		})
	}
}

func TestExchangeExportRejectsKindChangingSuffix(t *testing.T) {
	list := List{Entries: []Entry{{Type: DomainSuffix, Value: "*.192.0.2.1"}}}
	if data, _, err := Encode(JSON, list); len(data) != 0 || err == nil {
		t.Fatalf("expected export to reject kind-changing suffix, got %q (%v)", data, err)
	}
}

func TestExchangeKeepsNumericSuffixDistinctFromIP(t *testing.T) {
	got := Decode(Text, []byte("*.010.0.0.1\n10.0.0.1"))
	assertExchangeList(t, got, List{Entries: []Entry{
		{Type: DomainSuffix, Value: "010.0.0.1"},
		{Type: IPCIDR, Value: "10.0.0.1/32"},
	}})
}

func TestExchangeDuplicatesAndActivation(t *testing.T) {
	preview := Decode(Text, []byte("Example.COM\n*.example.com\n192.0.2.1\n192.0.2.1/32\nexample.net"))
	assertExchangeList(t, preview, List{Entries: []Entry{
		{Type: DomainSuffix, Value: "example.com"}, {Type: IPCIDR, Value: "192.0.2.1/32"}, {Type: DomainSuffix, Value: "example.net"},
	}})
	if preview.Duplicates != 2 {
		t.Fatalf("got %d duplicates, want 2", preview.Duplicates)
	}

	for _, firstDisabled := range []bool{false, true} {
		data := fmt.Appendf(nil, `{"version":1,"entries":[{"type":"domain_suffix","value":"Example.COM","disabled":%t},{"type":"domain_suffix","value":".example.com","disabled":%t}]}`, firstDisabled, !firstDisabled)
		preview = Decode(JSON, data)
		if preview.Valid || preview.Duplicates != 1 || len(preview.Issues) != 1 || preview.Issues[0].Location != "entries[1]" {
			t.Fatalf("conflicting activation was not rejected: %+v", preview)
		}
		if _, _, err := Encode(Text, List{Entries: []Entry{
			{Type: DomainSuffix, Value: "Example.COM", Disabled: firstDisabled}, {Type: DomainSuffix, Value: ".example.com", Disabled: !firstDisabled},
		}}); err == nil {
			t.Fatal("conflicting activation hidden by lossy export")
		}
	}
}

func TestExchangeLossyFormatsOmitDisabledEntries(t *testing.T) {
	list := List{Name: "Portable list", Entries: []Entry{
		{Type: DomainSuffix, Value: "active.example"}, {Type: DomainSuffix, Value: "disabled.example", Disabled: true},
	}}
	for _, format := range []Format{Text, CSV} {
		data, losses, err := Encode(format, list)
		if err != nil || len(losses) != 2 {
			t.Fatalf("encode %s: losses %v, error %v", format, losses, err)
		}
		assertExchangeList(t, Decode(format, data), List{Entries: list.Entries[:1]})
	}
}

func TestExchangeLimits(t *testing.T) {
	t.Run("file bytes", func(t *testing.T) {
		preview := Decode(Text, bytes.Repeat([]byte{' '}, MaxFileBytes+1))
		if preview.Valid || len(preview.Issues) != 1 {
			t.Fatalf("oversized file accepted: %+v", preview)
		}
	})
	t.Run("raw rows include duplicates", func(t *testing.T) {
		data := bytes.Repeat([]byte("example.com\n"), MaxEntries+1)
		preview := Decode(Text, data[:len(data)-len("example.com\n")])
		assertExchangeList(t, preview, List{Entries: []Entry{{Type: DomainSuffix, Value: "example.com"}}})
		preview = Decode(Text, data)
		if preview.Valid || len(preview.Issues) != 1 || preview.Duplicates != MaxEntries-1 {
			t.Fatalf("oversized row count accepted: %+v", preview)
		}
	})
	t.Run("JSON rows are limited before parsing excess", func(t *testing.T) {
		data := []byte(`{"version":1,"entries":[` + strings.Repeat(`{"type":"domain_suffix","value":"example.com"},`, MaxEntries) + `{}]}`)
		preview := Decode(JSON, data)
		if preview.Valid || preview.Duplicates != MaxEntries-1 || len(preview.Issues) != 1 || !strings.Contains(preview.Issues[0].Message, "20000") {
			t.Fatalf("oversized JSON row count accepted: %+v", preview)
		}
	})
	t.Run("CSV row width", func(t *testing.T) {
		data := []byte("type,value\n" + strings.Repeat(",", MaxFileBytes/2))
		preview := Decode(CSV, data)
		if preview.Valid || len(preview.Issues) != 1 || preview.Issues[0].Location != "line 2" ||
			!strings.Contains(preview.Issues[0].Message, "CSV row exceeds") {
			t.Fatalf("unbounded CSV row accepted: %+v", preview)
		}
	})
	t.Run("diagnostics", func(t *testing.T) {
		preview := Decode(Text, bytes.Repeat([]byte("*invalid\n"), 2*maxIssues))
		if preview.Valid || len(preview.Issues) != maxIssues || preview.OmittedIssues != maxIssues {
			t.Fatalf("diagnostics not bounded: issues=%d, omitted=%d, valid=%t", len(preview.Issues), preview.OmittedIssues, preview.Valid)
		}
	})
	t.Run("oversized name or value", func(t *testing.T) {
		value := strings.Repeat("x", maxValueBytes+1)
		preview := Decode(Text, []byte(value))
		if preview.Valid || len(preview.Issues) != 1 || strings.Contains(preview.Issues[0].Message, value) {
			t.Fatalf("oversized value not rejected safely: %+v", preview)
		}
		preview = Decode(JSON, []byte(fmt.Sprintf(`{"version":1,"entries":[],"name":%q}`, strings.Repeat("x", maxNameBytes+1))))
		if preview.Valid || len(preview.Issues) != 1 {
			t.Fatalf("oversized name accepted: %+v", preview)
		}
	})
}

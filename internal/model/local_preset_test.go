package model

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestLocalPresetsOmittedInOldConfig(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LocalPresets != nil {
		t.Fatalf("omitted presets = %v", cfg.LocalPresets)
	}
	for name, marshal := range map[string]func() ([]byte, error){
		"YAML": cfg.Marshal,
		"JSON": func() ([]byte, error) { return json.Marshal(cfg) },
	} {
		raw, err := marshal()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("local_presets")) {
			t.Errorf("%s includes absent local_presets", name)
		}
	}
}

func TestLocalPresetRoundTripAndActivation(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
local_presets:
  - id: example-list
    name: "Example rul\u00e9s"
    entries: ["Example.COM", "192.0.2.0/24", "2001:db8::7", "198.51.100.7"]
    disabled_entries: ["*.example.com", "2001:db8::7/128"]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []LocalPreset{{
		ID:              "example-list",
		Name:            "Example rul\u00e9s",
		Entries:         []string{"Example.COM", "192.0.2.0/24", "2001:db8::7", "198.51.100.7"},
		DisabledEntries: []string{"*.example.com", "2001:db8::7/128"},
	}}
	yaml, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Config
	if err := json.Unmarshal(rawJSON, &fromJSON); err != nil {
		t.Fatal(err)
	}
	for _, restored := range []*Config{cfg, fromYAML, &fromJSON, cfg.Clone()} {
		if !reflect.DeepEqual(restored.LocalPresets, want) {
			t.Fatalf("restored presets = %+v; want %+v", restored.LocalPresets, want)
		}
		if len(restored.Groups) != 2 || restored.Groups[0].Preset != nil || restored.Groups[1].Preset != nil {
			t.Fatalf("local presets modified routing groups: %+v", restored.Groups)
		}
		preset := restored.LocalPresets[0]
		active := []string{"192.0.2.0/24", "198.51.100.7"}
		if got := slices.Collect(preset.ActiveEntries()); !slices.Equal(got, active) {
			t.Errorf("active preset entries = %v; want %v", got, active)
		}
		group := Group{Entries: preset.Entries, DisabledEntries: preset.DisabledEntries}
		if got := slices.Collect(group.ActiveEntries()); !slices.Equal(got, active) {
			t.Errorf("active copied group entries = %v; want %v", got, active)
		}
	}
}

func TestLocalPresetUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(validYAML + `
local_presets:
  - id: example
    name: Example
    target: direct
`))
	if err == nil || !strings.Contains(err.Error(), "field target not found") {
		t.Fatalf("expected rejection of a group-only field, got %v", err)
	}
}

func TestLocalPresetValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"empty ID", func(c *Config) { c.LocalPresets[0].ID = "" }, "local_presets[0].id"},
		{"invalid ID", func(c *Config) { c.LocalPresets[0].ID = "-Example_" }, "local_presets[0].id"},
		{"long ID", func(c *Config) { c.LocalPresets[0].ID = strings.Repeat("a", 41) }, "up to 40"},
		{"duplicate ID", func(c *Config) {
			c.LocalPresets = append(c.LocalPresets, LocalPreset{ID: "example", Name: "Other"})
		}, "local_presets[1].id: duplicate"},
		{"blank name", func(c *Config) { c.LocalPresets[0].Name = " \t\n" }, "name: required"},
		{"long name", func(c *Config) { c.LocalPresets[0].Name = strings.Repeat("\u00e9", 65) }, "up to 64"},
		{"invalid UTF-8 name", func(c *Config) { c.LocalPresets[0].Name = "\xff" }, "name: must be valid UTF-8"},
		{"invalid entry", func(c *Config) { c.LocalPresets[0].Entries = []string{"https://example.com"} }, "entries[0]: not a domain"},
		{"invalid UTF-8 entry", func(c *Config) { c.LocalPresets[0].Entries = []string{"example.com # \xff"} }, "entries[0]: must be valid UTF-8"},
		{"long entry", func(c *Config) {
			c.LocalPresets[0].Entries = []string{"example.com # " + strings.Repeat("x", MaxLocalPresetEntryBytes)}
		}, "entries[0]: exceeds"},
		{"duplicate domain", func(c *Config) {
			c.LocalPresets[0].Entries = []string{"EXAMPLE.COM", ".example.com."}
		}, "entries[1]: duplicate"},
		{"duplicate prefix", func(c *Config) {
			c.LocalPresets[0].Entries = []string{"192.0.2.1/24", "192.0.2.0/24"}
		}, "entries[1]: duplicate"},
		{"invalid disabled entry", func(c *Config) {
			c.LocalPresets[0].DisabledEntries = []string{"localhost"}
		}, "disabled_entries[0]: not a domain"},
		{"unknown disabled entry", func(c *Config) {
			c.LocalPresets[0].DisabledEntries = []string{"other.example"}
		}, "disabled_entries[0]: not in entries"},
		{"duplicate disabled entry", func(c *Config) {
			c.LocalPresets[0].DisabledEntries = []string{"Example.COM", "*.example.com"}
		}, "disabled_entries[1]: duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{LocalPresets: []LocalPreset{{ID: "example", Name: "Example", Entries: []string{"example.com"}}}}
			cfg.Defaults()
			tc.edit(cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v; want %q", err, tc.want)
			}
		})
	}
}

func TestLocalPresetBudgets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		presets []LocalPreset
		want    string
	}{
		{"preset count", make([]LocalPreset, MaxLocalPresets+1), "local_presets: at most"},
		{"entries per preset", []LocalPreset{{Entries: make([]string, MaxLocalPresetEntries+1)}}, "local_presets[0].entries: at most"},
		{"disabled markers per preset", []LocalPreset{{DisabledEntries: make([]string, MaxLocalPresetEntries+1)}}, "local_presets[0].disabled_entries: at most"},
		{"total values", []LocalPreset{
			{Entries: make([]string, MaxLocalPresetEntries), DisabledEntries: make([]string, MaxLocalPresetEntries)},
			{Entries: []string{"example.com"}},
		}, "local_presets: at most 40000 entry values"},
		{"total entry bytes", []LocalPreset{{
			Entries: slices.Repeat([]string{strings.Repeat("x", MaxLocalPresetEntryBytes)}, MaxLocalPresetTotalBytes/MaxLocalPresetEntryBytes+1),
		}}, "local_presets: at most 1048576 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{LocalPresets: tc.presets}
			cfg.Defaults()
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v; want %q", err, tc.want)
			}
		})
	}
}

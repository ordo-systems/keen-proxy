package model

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Local preset limits bound validation and the size of the saved collection.
const (
	MaxLocalPresets           = 64
	MaxLocalPresetEntries     = 20_000
	MaxLocalPresetEntryBytes  = 1_024
	MaxLocalPresetTotalValues = 40_000  // includes disabled markers
	MaxLocalPresetTotalBytes  = 1 << 20 // includes disabled markers
)

const maxLocalPresetIDBytes = 40

var localPresetID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// LocalPreset stores reusable resource entries without a routing target or
// catalog provenance. It has no effect until its entries are copied to a group.
type LocalPreset struct {
	ID              string   `yaml:"id" json:"id"`
	Name            string   `yaml:"name" json:"name"`
	Entries         []string `yaml:"entries,omitempty" json:"entries"`
	DisabledEntries []string `yaml:"disabled_entries,omitempty" json:"disabled_entries,omitempty"`
}

func (c *Config) validateLocalPresets(add func(string, ...any)) {
	if !localPresetBudgetOK(c.LocalPresets, add) {
		return
	}
	ids := make(map[string]struct{}, len(c.LocalPresets))
	for i, p := range c.LocalPresets {
		where := fmt.Sprintf("local_presets[%d]", i)
		if len(p.ID) > maxLocalPresetIDBytes || !localPresetID.MatchString(p.ID) {
			add("%s.id: use lowercase Latin letters, digits and hyphens, starting with a letter or digit (up to %d characters)", where, maxLocalPresetIDBytes)
		} else if _, exists := ids[p.ID]; exists {
			add("%s.id: duplicate id %q", where, p.ID)
		} else {
			ids[p.ID] = struct{}{}
		}
		switch {
		case len(p.Name) > 64*utf8.UTFMax || utf8.RuneCountInString(p.Name) > 64:
			add("%s.name: use up to 64 characters", where)
		case !utf8.ValidString(p.Name):
			add("%s.name: must be valid UTF-8", where)
		case strings.TrimSpace(p.Name) == "":
			add("%s.name: required", where)
		}
		p.validateEntries(where, add)
	}
}

// Check aggregate budgets before parsing any resource or allocating identity maps.
func localPresetBudgetOK(presets []LocalPreset, add func(string, ...any)) bool {
	if len(presets) > MaxLocalPresets {
		add("local_presets: at most %d presets", MaxLocalPresets)
		return false
	}
	values, bytesLeft := 0, MaxLocalPresetTotalBytes
	for i, p := range presets {
		if len(p.Entries) > MaxLocalPresetEntries {
			add("local_presets[%d].entries: at most %d entries", i, MaxLocalPresetEntries)
			return false
		}
		if len(p.DisabledEntries) > MaxLocalPresetEntries {
			add("local_presets[%d].disabled_entries: at most %d entries", i, MaxLocalPresetEntries)
			return false
		}
		values += len(p.Entries) + len(p.DisabledEntries)
		if values > MaxLocalPresetTotalValues {
			add("local_presets: at most %d entry values including disabled markers", MaxLocalPresetTotalValues)
			return false
		}
		for _, entries := range [...][]string{p.Entries, p.DisabledEntries} {
			for _, raw := range entries {
				bytesLeft -= len(raw)
				if bytesLeft < 0 {
					add("local_presets: at most %d bytes of entry values including disabled markers", MaxLocalPresetTotalBytes)
					return false
				}
			}
		}
	}
	return true
}

func (p LocalPreset) validateEntries(where string, add func(string, ...any)) {
	// A known key starts active and becomes disabled on the first matching marker.
	entries := make(map[string]bool, len(p.Entries))
	for i, raw := range p.Entries {
		entry, err := parseLocalPresetEntry(raw)
		if err != nil {
			add("%s.entries[%d]: %v", where, i, err)
		} else if _, exists := entries[entry]; exists {
			add("%s.entries[%d]: duplicate entry", where, i)
		} else {
			entries[entry] = false
		}
	}
	for i, raw := range p.DisabledEntries {
		entry, err := parseLocalPresetEntry(raw)
		disabled, exists := entries[entry]
		switch {
		case err != nil:
			add("%s.disabled_entries[%d]: %v", where, i, err)
		case !exists:
			add("%s.disabled_entries[%d]: not in entries", where, i)
		case disabled:
			add("%s.disabled_entries[%d]: duplicate entry", where, i)
		default:
			entries[entry] = true
		}
	}
}

func parseLocalPresetEntry(raw string) (string, error) {
	if len(raw) > MaxLocalPresetEntryBytes {
		return "", fmt.Errorf("exceeds %d bytes", MaxLocalPresetEntryBytes)
	}
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("must be valid UTF-8")
	}
	entry, err := ParseEntry(raw)
	if err != nil {
		return "", err
	}
	return entry.String(), nil
}

// Package catalog contains bundled community routing presets.
package catalog

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

//go:embed presets.json
var data embed.FS

// Preset is a domain and optional IP-prefix routing collection.
type Preset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Domains     []string `json:"domains"`
	Prefixes    []string `json:"prefixes"`
	Description string   `json:"description"`
}

// Presets contains the embedded catalog loaded at package initialization.
var Presets = load()

func load() []Preset {
	raw, _ := data.ReadFile("presets.json")
	var p []Preset
	if err := json.Unmarshal(raw, &p); err != nil {
		panic(err)
	}
	return p
}

// revision derives update identity from routing content rather than export metadata.
func (p Preset) revision() string {
	raw, _ := json.Marshal([2][]string{p.Domains, p.Prefixes})
	return fmt.Sprintf("sha256-%x", sha256.Sum256(raw))
}

// Find returns the catalog preset with the given ID, if present.
func Find(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// Diff records sorted entry additions and removals for a preset preview.
type Diff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

func normalized(entries []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range entries {
		e, err := model.ParseEntry(s)
		if err == nil {
			m[e.String()] = true
		}
	}
	return m
}

// suffixParents visits proper DNS-label ancestors, not arbitrary string suffixes.
func suffixParents(domain string, visit func(string) bool) bool {
	for {
		_, parent, ok := strings.Cut(domain, ".")
		if !ok {
			return false
		}
		if visit(parent) {
			return true
		}
		domain = parent
	}
}

// Update merges a catalog revision while preserving user additions, exclusions, and opt-in state.
func Update(g model.Group, p Preset) (model.Group, Diff) {
	current := normalized(g.Entries)
	off := normalized(g.DisabledEntries)
	base := map[string]bool{}
	auto := false
	if g.Preset != nil {
		base = normalized(g.Preset.Base)
		auto = g.Preset.AutoUpdate
	}
	next := normalized(p.Domains)
	// Deleted baseline entries are persistent user exclusions. Keep their history
	// in Base even if a later catalog revision temporarily removes the domain.
	excluded := map[string]bool{}
	for s := range base {
		if !current[s] && !off[s] {
			excluded[s] = true
			delete(next, s)
		}
	}
	// New overlapping suffixes must not re-enable previously excluded traffic.
	// Leave them out of Base so they do not become exclusions themselves.
	if len(excluded) != 0 || len(off) != 0 {
		parentOfExcluded := make(map[string]bool)
		addParents := func(s string) {
			if e, err := model.ParseEntry(s); err == nil && e.Kind == model.EntryDomain {
				suffixParents(s, func(parent string) bool {
					parentOfExcluded[parent] = true
					return false
				})
			}
		}
		for s := range excluded {
			addParents(s)
		}
		for s := range off {
			addParents(s)
		}
		for s := range next {
			if current[s] || base[s] || off[s] {
				continue
			}
			if parentOfExcluded[s] || suffixParents(s, func(parent string) bool {
				return excluded[parent] || off[parent]
			}) {
				delete(next, s)
			}
		}
	}
	for s := range current {
		if !base[s] {
			next[s] = true
		}
	}
	out := []string{}
	diff := Diff{Added: []string{}, Removed: []string{}}
	for s := range next {
		out = append(out, s)
		if !current[s] {
			diff.Added = append(diff.Added, s)
		}
	}
	for s := range current {
		if !next[s] {
			diff.Removed = append(diff.Removed, s)
		}
	}
	sort.Strings(out)
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	for s := range current {
		if !base[s] {
			delete(next, s)
		}
	}
	for s := range excluded {
		next[s] = true
	}
	baseline := []string{}
	for s := range next {
		baseline = append(baseline, s)
	}
	sort.Strings(baseline)
	g.Entries = out
	g.Preset = &model.Preset{ID: p.ID, Version: p.revision(), Base: baseline, AutoUpdate: auto}
	return g, diff
}

// AutoUpdate refreshes only explicitly opted-in installations on app upgrade.
func AutoUpdate(c *model.Config) {
	for i, g := range c.Groups {
		if g.Preset != nil && g.Preset.AutoUpdate {
			if p, ok := Find(g.Preset.ID); ok && p.revision() != g.Preset.Version {
				c.Groups[i], _ = Update(g, p)
			}
		}
	}
}

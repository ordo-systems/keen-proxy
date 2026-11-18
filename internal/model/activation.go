package model

import (
	"iter"
	"strings"
)

// ActiveChain retains fallback order while bypassing disabled profiles. An empty
// effective chain blocks traffic; it must never become an implicit direct exit.
func (c *Config) ActiveChain(id string) []string {
	chain := c.Chain(id)
	active := chain[:0]
	for _, member := range chain {
		if member == TargetDirect {
			active = append(active, member)
			continue
		}
		for _, cn := range c.Connections {
			if cn.ID == member && !cn.Disabled {
				active = append(active, member)
				break
			}
		}
	}
	if len(active) == 0 {
		return append(active, TargetBlock)
	}
	return active
}

// ActiveEntries yields original entries in order using the canonical entry
// identity for activation. Parent activation never changes persisted child state.
func (g Group) ActiveEntries() iter.Seq[string] {
	return activeValues(g.Entries, g.DisabledEntries, g.Disabled, entryIdentity)
}

// ActiveEntries yields reusable entries in order, excluding disabled resources.
func (p LocalPreset) ActiveEntries() iter.Seq[string] {
	return activeValues(p.Entries, p.DisabledEntries, false, entryIdentity)
}

func entryIdentity(raw string) string {
	e, err := ParseEntry(raw)
	if err != nil {
		return raw
	}
	return e.String()
}

// ActiveCountries yields enabled country selectors in configuration order.
func (g Group) ActiveCountries() iter.Seq[string] {
	return activeValues(g.Countries, g.DisabledCountries, g.Disabled, geoIdentity)
}

// ActiveCategories yields enabled category selectors in configuration order.
func (g Group) ActiveCategories() iter.Seq[string] {
	return activeValues(g.Categories, g.DisabledCategories, g.Disabled, geoIdentity)
}

func geoIdentity(value string) string { return strings.ToUpper(strings.TrimSpace(value)) }

func activeValues(values, disabled []string, parentOff bool, identity func(string) string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if parentOff {
			return
		}
		var off map[string]bool
		if len(disabled) > 0 {
			off = make(map[string]bool, len(disabled))
			for _, value := range disabled {
				off[identity(value)] = true
			}
		}
		for _, value := range values {
			if len(off) > 0 && off[identity(value)] {
				continue
			}
			if !yield(value) {
				return
			}
		}
	}
}

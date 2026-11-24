package catalog

import (
	"slices"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestPresetReintroducedOffEntryIsNotDeleted(t *testing.T) {
	g := model.Group{Name: "preset", Target: "direct", Disabled: true, Entries: []string{"off.example", "local.example"}, DisabledEntries: []string{"OFF.EXAMPLE"}, Preset: &model.Preset{ID: "test", Version: "old", Base: []string{"off.example", "deleted.example"}, AutoUpdate: true}}
	g, _ = Update(g, Preset{ID: "test", Domains: []string{"other.example"}})
	g, _ = Update(g, Preset{ID: "test", Domains: []string{"off.example", "deleted.example", "other.example"}})
	if !slices.Contains(g.Entries, "off.example") || !slices.Contains(g.Entries, "local.example") || slices.Contains(g.Entries, "deleted.example") {
		t.Fatalf("merge = %v", g.Entries)
	}
	if !g.Disabled || !g.Preset.AutoUpdate || !slices.Equal(g.DisabledEntries, []string{"OFF.EXAMPLE"}) {
		t.Fatalf("activation state lost: %+v", g)
	}
	g.Disabled = false
	if slices.Contains(slices.Collect(g.ActiveEntries()), "off.example") {
		t.Fatal("reintroduced off entry became active")
	}
}

func TestPresetUpdateDoesNotReopenExcludedSuffixes(t *testing.T) {
	g := model.Group{
		Entries:         []string{"disabled.example", "manual.deleted.example"},
		DisabledEntries: []string{"disabled.example"},
		Preset: &model.Preset{
			ID: "test", Base: []string{"disabled.example", "child.deleted.example"},
		},
	}
	p := Preset{ID: "test", Domains: []string{
		"disabled.example", "cdn.disabled.example", "child.deleted.example",
		"deleted.example", "unrelated.example",
	}}
	g, diff := Update(g, p)
	if !slices.Equal(g.Entries, []string{"disabled.example", "manual.deleted.example", "unrelated.example"}) {
		t.Fatalf("entries = %v", g.Entries)
	}
	if !slices.Equal(diff.Added, []string{"unrelated.example"}) {
		t.Fatalf("preview additions = %v", diff.Added)
	}
	g, diff = Update(g, p)
	if len(diff.Added) != 0 || slices.Contains(g.Entries, "cdn.disabled.example") || slices.Contains(g.Entries, "deleted.example") {
		t.Fatalf("repeated update reopened exclusions: %v (%+v)", g.Entries, diff)
	}
}

func TestBundledPresetsDoNotRouteUnrelatedSuffixes(t *testing.T) {
	for _, tc := range []struct {
		id, retained string
		rejected     []string
	}{
		{"ru-state", "zakupki.gov.ru", []string{"cbg.ru", "edu.ru", "marine.ru"}},
		{"ru-essential", "avito.st", []string{"yandex.com", "yandex.net", "telemost.yandex.net"}},
		{"ru-social", "st-ok.cdn-vk.ru", []string{"cdn-vk.ru", "skillbox.ru", "tarantool.io", "my.games"}},
	} {
		p, ok := Find(tc.id)
		if !ok || !slices.Contains(p.Domains, tc.retained) {
			t.Fatalf("%s lacks %s", tc.id, tc.retained)
		}
		for _, name := range tc.rejected {
			if slices.Contains(p.Domains, name) {
				t.Errorf("%s includes unrelated suffix %s", tc.id, name)
			}
		}
	}
}

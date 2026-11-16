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

package catalog

import (
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestCatalogAndManagedUpdates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets {
		if seen[p.ID] || len(p.Domains) == 0 || p.ID == "" {
			t.Fatal(p)
		}
		seen[p.ID] = true
		for _, s := range p.Domains {
			if _, e := model.ParseEntry(s); e != nil {
				t.Fatal(p.ID, s, e)
			}
		}
	}
	// Saved groups refer to these IDs by name. Adding a preset must not break CI.
	for _, id := range strings.Fields(`
		apple aqara atlassian battlenet battleye claude codeium deepl discord docker
		ea epic gemini github gitlab google ha-cloud hue manus microsoft miro netflix
		nintendo notion nvidia openai playstation riot ru-banks ru-essential ru-finance
		ru-sber ru-social ru-state ru-video signal slack smartthings sonos spotify steam
		supercell telegram telemost tidal tiktok tmdb tuya twitch vimeo vk warthunder
		wb-games whatsapp windsurf xbox xiaomi yandex yandex-home yeelight youtube zoom
	`) {
		if !seen[id] {
			t.Errorf("missing bundled preset ID %q", id)
		}
	}

	old := model.Group{Name: "custom title", Target: "direct", Entries: []string{"keep.test", "mine.test"}, Preset: &model.Preset{ID: "test", Version: "old", Base: []string{"keep.test", "deleted.test"}}}
	p := Preset{ID: "test", Domains: []string{"keep.test", "deleted.test", "new.test"}}
	g, diff := Update(old, p)
	if !slices.Equal(g.Entries, []string{"keep.test", "mine.test", "new.test"}) {
		t.Fatal(g.Entries)
	}
	if g.Name != old.Name || g.Target != old.Target || g.Preset.Version != p.revision() || !slices.Equal(diff.Added, []string{"new.test"}) {
		t.Fatal(g, diff)
	}
}

func TestUserAdditionSurvivesCatalogRoundTrip(t *testing.T) {
	g := model.Group{Entries: []string{"a.test", "mine.test"}, Preset: &model.Preset{ID: "t", Version: "1", Base: []string{"a.test"}}}
	g, _ = Update(g, Preset{ID: "t", Domains: []string{"a.test", "mine.test"}})
	g, _ = Update(g, Preset{ID: "t", Domains: []string{"a.test"}})
	if !slices.Contains(g.Entries, "mine.test") {
		t.Fatal("manual addition lost")
	}
}

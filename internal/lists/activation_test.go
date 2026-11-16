package lists

import (
	"net/netip"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestDisabledEntriesFallThroughInOrder(t *testing.T) {
	groups := []model.Group{
		{Target: model.TargetBlock, Entries: []string{"Example.COM", "192.0.2.0/24"}, DisabledEntries: []string{"*.example.com", "192.0.2.17/24"}},
		{Target: model.TargetDirect, Entries: []string{"example.com", "192.0.2.0/24"}},
	}
	m := New(groups)
	if got := m.Domain("www.example.com"); got != 1 {
		t.Fatalf("domain group = %d", got)
	}
	if got := m.Addr(netip.MustParseAddr("192.0.2.42")); got != 1 {
		t.Fatalf("address group = %d", got)
	}
	groups[1].Disabled = true
	m = New(groups)
	if m.Domain("example.com") != NoMatch || m.Addr(netip.MustParseAddr("192.0.2.42")) != NoMatch {
		t.Fatal("inactive rule still matches")
	}
}

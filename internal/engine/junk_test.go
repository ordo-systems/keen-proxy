package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

func TestCoreDecodedJunkBudget(t *testing.T) {
	for _, raw := range []string{
		`{"endpoints":[{"type":"wireguard","tag":"raw","JC":256,"JMIN":65535,"JMAX":0}]}`,
		`{"endpoints":[{"type":"wireguard","tag":"raw","JC":256,"JMIN":65535}]}`,
		`{"endpoints":[{"type":"wireguard","tag":"raw","Jc":256,"jmax":4097}]}`,
	} {
		opts := decodeCore(t, raw)
		wg := wireGuardOptions(t, opts)
		if wg.Jc != 256 || (wg.Jmin != 65535 && wg.Jmax != 4097) {
			t.Fatalf("core did not fold junk aliases: %s %#v", raw, wg)
		}
		if err := rejectEndpointJunk(opts); err == nil || !strings.Contains(err.Error(), "junk packet burst") {
			t.Fatalf("decoded burst accepted: %s %v", raw, err)
		}
		if err := Validate(context.Background(), []byte(raw)); err == nil || !strings.Contains(err.Error(), "junk packet burst") {
			t.Fatalf("validation constructed or accepted burst: %s %v", raw, err)
		}
	}
	opts := decodeCore(t, `{"endpoints":[{"type":"wireguard","tag":"raw","JC":256,"JMAX":4096}]}`)
	wg := wireGuardOptions(t, opts)
	if wg.Jc != 256 || wg.Jmax != 4096 || wg.Jmin != 0 {
		t.Fatalf("core lost alias boundary: %#v", wg)
	}
	if err := rejectEndpointJunk(opts); err != nil {
		t.Fatal(err)
	}
	opts = decodeCore(t, `{"endpoints":[{"type":"wireguard","tag":"raw","JC":256,"JMIN":4096}]}`)
	wg = wireGuardOptions(t, opts)
	if wg.Jmax != 0 || wg.Jmin != 4096 {
		t.Fatalf("omitted JMAX was not a zero default: %#v", wg)
	}
	if err := rejectEndpointJunk(opts); err != nil {
		t.Fatal("jmin at the payload cap with jmax omitted:", err)
	}
	if _, err := decodeOptions(context.Background(), []byte(`{"endpoints":[{"type":"wireguard","tag":"plain"}]}`)); err != nil {
		t.Fatal("default sizes rejected:", err)
	}
}

func decodeCore(t *testing.T, raw string) option.Options {
	t.Helper()
	opts, err := sjson.UnmarshalExtendedContext[option.Options](Context(context.Background()), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

func wireGuardOptions(t *testing.T, opts option.Options) *option.WireGuardEndpointOptions {
	t.Helper()
	wg, ok := opts.Endpoints[0].Options.(*option.WireGuardEndpointOptions)
	if !ok || wg == nil {
		t.Fatalf("core did not decode a WireGuard endpoint: %#v", opts.Endpoints)
	}
	return wg
}

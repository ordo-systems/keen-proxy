package engine

import (
	"context"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/ordo-systems/keen-proxy/internal/awg"
)

// Validate checks schemas and constructors without starting listeners, polling,
// external clients or network connections. The caller supplies profiles only.
func Validate(ctx context.Context, config []byte) error {
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{Context: Context(ctx), Options: options})
	if err != nil {
		return err
	}
	return instance.Close()
}

func decodeOptions(ctx context.Context, config []byte) (option.Options, error) {
	ctx = Context(ctx)
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return option.Options{}, err
	}
	if err := rejectEndpointJunk(options); err != nil {
		return option.Options{}, err
	}
	return options, nil
}

// rejectEndpointJunk runs after the core decoder has folded field names into
// WireGuardEndpointOptions. A parallel raw-map check misses JC/JMIN/JMAX.
func rejectEndpointJunk(options option.Options) error {
	for _, endpoint := range options.Endpoints {
		wg, ok := endpoint.Options.(*option.WireGuardEndpointOptions)
		if !ok || wg == nil {
			continue
		}
		if err := awg.DeviceJunkBudget(uint64(wg.Jc), uint64(wg.Jmin), uint64(wg.Jmax)); err != nil {
			return fmt.Errorf("endpoint %q: %w", endpoint.Tag, err)
		}
	}
	return nil
}

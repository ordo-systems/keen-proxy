package api

import (
	"context"

	"github.com/miekg/dns"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// CheckDNS reports effective demo policy, never a claim of network verification.
func (d *Demo) CheckDNS(_ context.Context, cfg *model.Config) (daemon.DNSCheck, error) {
	if err := cfg.Validate(); err != nil {
		return daemon.DNSCheck{}, err
	}
	check := daemon.DNSCheck{Demo: true, Route: cfg.DNS.Route, Error: "Demo: network requests are disabled"}
	if cfg.DNS.Route == "connection" {
		check.Route = "connection:" + cfg.DNS.Connection
		active := demoActive(cfg, cfg.DNS.Connection)
		if active == model.TargetBlock || active == model.TargetDirect {
			if cfg.DNS.Failure == "direct" {
				check.Route = "direct-fallback"
			} else {
				check.Route = "unavailable"
				check.RCode = dns.RcodeServerFailure
				check.Error = "Demo: DNS connection is unavailable"
			}
		}
	}
	return check, nil
}

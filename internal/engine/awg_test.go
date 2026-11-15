package engine

import (
	"context"
	"fmt"
	"testing"
)

// Validate must reject broken obfuscation before Apply stops a working engine.
func TestValidateAWGProfile(t *testing.T) {
	profile := func(fields string) []byte {
		return []byte(fmt.Sprintf(`{"log":{"disabled":true},"endpoints":[{"type":"wireguard","tag":"awg","address":["10.77.0.2/32"],"private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","peers":[{"address":"127.0.0.1","port":51820,"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","allowed_ips":["0.0.0.0/0"]}],%s}]}`, fields))
	}
	if err := Validate(context.Background(), profile(`"jc":2,"jmin":40,"jmax":60,"s1":20,"s2":30,"h1":"100-200","h2":300,"h3":400,"h4":500`)); err != nil {
		t.Fatalf("valid AWG profile: %v", err)
	}
	for _, fields := range []string{
		`"jc":2,"jmin":80,"jmax":40`,
		`"h1":"200-100"`,
		`"header_protection_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","s1":1,"s2":12,"s3":12,"s4":12`,
	} {
		if err := Validate(context.Background(), profile(fields)); err == nil {
			t.Errorf("accepted invalid obfuscation: %s", fields)
		}
	}
}

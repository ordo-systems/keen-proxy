package model

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// A valid memory recommendation must survive parse, save, clone, and the JSON API encoding.
func TestSystemMemoryLimitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		mib   MemoryLimitMiB
		bytes int64
	}{{1, 1048576}, {400, 419430400}, {8796093022207, 9223372036853727232}} {
		value := tc.mib
		text := strconv.FormatInt(int64(value), 10)
		t.Run(text, func(t *testing.T) {
			cfg, err := Parse([]byte("system:\n  memory_limit_mib: " + text + "\n"))
			if err != nil {
				t.Fatalf("valid memory limit rejected: %v", err)
			}
			if cfg.System.MemoryLimitMiB == nil || *cfg.System.MemoryLimitMiB != value {
				t.Fatalf("parsed limit = %v, want %d", cfg.System.MemoryLimitMiB, value)
			}
			raw, err := cfg.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "memory_limit_mib: "+text) {
				t.Fatalf("memory recommendation lost during save: %s", raw)
			}
			again, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if again.System.MemoryLimitMiB == nil || *again.System.MemoryLimitMiB != value {
				t.Fatalf("reload lost limit: %v", again.System.MemoryLimitMiB)
			}
			cloned := cfg.Clone()
			*cfg.System.MemoryLimitMiB = 1
			if cloned.System.MemoryLimitMiB == nil || *cloned.System.MemoryLimitMiB != value {
				t.Fatalf("clone shares or lost the memory limit: %v", cloned.System.MemoryLimitMiB)
			}
			got, ok := MemoryLimitBytes(again, 1)
			if !ok || got != tc.bytes {
				t.Fatalf("byte conversion = %d ok=%v", got, ok)
			}
		})
	}
	for _, value := range []string{"0", "-1", "8796093022208", "1.5", "400.5", "8796093022207.5"} {
		t.Run("reject_"+value, func(t *testing.T) {
			if _, err := Parse([]byte("system:\n  memory_limit_mib: " + value + "\n")); err == nil {
				t.Fatal("invalid memory limit accepted")
			}
		})
	}
	if _, ok := MemoryLimitBytes(&Config{System: System{MemoryLimitMiB: new(MemoryLimitMiB(0))}}, 99); ok {
		t.Fatal("zero was convertible to a runtime limit")
	}
}

// Existing configurations and an explicit null keep the process-start memory limit.
func TestSystemMemoryLimitOptional(t *testing.T) {
	for _, raw := range []string{"{}\n", "system:\n  memory_limit_mib: null\n", "system: {}\n"} {
		cfg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatalf("%q rejected: %v", raw, err)
		}
		if cfg.System.MemoryLimitMiB != nil {
			t.Fatalf("%q became an override: %d", raw, *cfg.System.MemoryLimitMiB)
		}
		saved, err := cfg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(saved), "memory_limit_mib") {
			t.Fatalf("absent limit was saved: %s", saved)
		}
		if got, ok := MemoryLimitBytes(cfg, 99); !ok || got != 99 {
			t.Fatalf("inherit = %d ok=%v", got, ok)
		}
	}
}

// The management API encodes this struct directly, so JSON must preserve and clear the field.
func TestSystemMemoryLimitJSON(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"system":{"memory_limit_mib":400}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Defaults()
	if cfg.System.MemoryLimitMiB == nil || *cfg.System.MemoryLimitMiB != 400 {
		t.Fatalf("json limit = %v", cfg.System.MemoryLimitMiB)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"memory_limit_mib":400`) {
		t.Fatalf("json lost the limit: %s", encoded)
	}
	if err := json.Unmarshal([]byte(`{"system":{"memory_limit_mib":null}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.System.MemoryLimitMiB != nil {
		t.Fatal("json null kept an override")
	}
}

func TestSystemMemoryLimitKeepsStrictYAMLFields(t *testing.T) {
	if _, err := Parse([]byte("system:\n  memory_limt_mib: 400\n")); err == nil {
		t.Fatal("misspelled system field accepted")
	}
}

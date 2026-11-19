package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestStartupStateRequiresAnActiveDaemonOrAPIBindWhenParked(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { occupied.Close() })

	for _, tc := range []struct {
		name       string
		addr       string
		mode       string
		listenFail bool
	}{
		{name: "parked and bound", addr: "127.0.0.1:0", mode: "management-only"},
		{name: "parked but cannot bind", addr: occupied.Addr().String(), mode: "management-only", listenFail: true},
		{name: "active even if API cannot bind", addr: occupied.Addr().String(), mode: "active", listenFail: true},
		{name: "bound without startup outcome", addr: "127.0.0.1:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &model.Config{API: model.API{Listen: tc.addr, TokenFile: filepath.Join(dir, "token")}}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			path := filepath.Join(dir, "startup-state")
			state := make(chan string, 1)
			listening := make(chan context.Context, 1)
			if tc.mode != "" {
				state <- tc.mode
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			called := false
			err := serveAPI(ctx, cfg, api.NewDemo(cfg), nil, log, func(apiCtx context.Context) {
				called = true
				listening <- apiCtx
				if tc.mode == "" {
					cancel()
				}
				publishStartupState(ctx, state, listening, path, log)
				cancel()
			})
			if (err != nil) != tc.listenFail || called == tc.listenFail {
				t.Fatalf("serveAPI: error = %v, listening callback called = %t", err, called)
			}
			if tc.listenFail {
				if tc.mode != "active" {
					cancel()
				}
				publishStartupState(ctx, state, listening, path, log)
			}
			got, err := os.ReadFile(path)
			if tc.mode == "active" || (tc.mode == "management-only" && !tc.listenFail) {
				if want := fmt.Sprintf("%s %d\n", tc.mode, os.Getpid()); err != nil || string(got) != want {
					t.Fatalf("startup state = %q, %v; want %q", got, err, want)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("unexpected startup state = %q, %v", got, err)
			}
		})
	}
}

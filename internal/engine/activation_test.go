package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Exercise dependency dispatch and stream forwarding, not only schema decoding.
func TestDisabledRawDetourFollowsFallbackOrBlocks(t *testing.T) {
	for _, fallback := range []string{"reserve", ""} {
		t.Run("fallback="+fallback, func(t *testing.T) {
			connected := make(chan string, 1)
			var tunnels sync.WaitGroup
			// SOCKS is supported by both registries; HTTP outbounds are full-only.
			proxy, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = proxy.Close(); tunnels.Wait() })
			tunnels.Add(1)
			go func() {
				defer tunnels.Done()
				conn, err := proxy.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				var greeting [9]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 4 || greeting[1] != 1 || greeting[8] != 0 {
					return
				}
				select {
				case connected <- net.JoinHostPort(net.IP(greeting[4:8]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(greeting[2:4])))):
				default:
					return
				}
				if _, err := conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				defer request.Body.Close()
				if request.Method != http.MethodGet {
					return
				}
				const body = "synthetic reserve stream"
				response := http.Response{
					StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
					ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)),
				}
				_ = response.Write(conn)
			}()
			cfg := &model.Config{Connections: []model.Connection{
				{ID: "primary", Type: model.ConnLink, Link: "socks5://203.0.113.1:1080", Disabled: true, Fallback: fallback},
				{ID: "dependent", Type: model.ConnSingBox, Outbound: map[string]any{
					"type": "socks", "version": "4", "server": "127.0.0.1", "server_port": proxy.Addr().(*net.TCPAddr).Port, "detour": "primary",
				}},
				{ID: "reserve", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
			}}
			cfg.Defaults()
			plan, err := compile.Compile(compile.Input{Config: cfg})
			if err != nil {
				t.Fatal(err)
			}
			var runtime struct {
				Log struct {
					Disabled bool `json:"disabled"`
				} `json:"log"`
				Outbounds json.RawMessage `json:"outbounds"`
			}
			if err := json.Unmarshal(plan.SingBox, &runtime); err != nil {
				t.Fatal(err)
			}
			runtime.Log.Disabled = true
			raw, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			var core Engine
			t.Cleanup(func() { _ = core.Close() })
			if _, err := core.Apply(raw); err != nil {
				t.Fatal(err)
			}
			outbound, base, ok := core.Outbound("dependent")
			if !ok {
				t.Fatal("dependent outbound missing")
			}
			ctx, cancel := context.WithTimeout(base, 5*time.Second)
			t.Cleanup(cancel)
			conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr("198.51.100.123:443"))
			if fallback == "" {
				if err == nil {
					_ = conn.Close()
					t.Fatal("disabled detour without a reserve allowed traffic")
				}
				select {
				case host := <-connected:
					t.Fatalf("blocked detour reached proxy for %s", host)
				default:
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = response.Body.Close() })
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "synthetic reserve stream" {
				t.Fatalf("reserve response: %d %q %v", response.StatusCode, body, err)
			}
			select {
			case got := <-connected:
				if got != "198.51.100.123:443" {
					t.Fatalf("detour destination = %q", got)
				}
			default:
				t.Fatal("reserve stream bypassed the configured proxy")
			}
			if cfg.Connections[1].Outbound["detour"] != "primary" || cfg.Connections[1].Outbound["tag"] != nil {
				t.Fatal("compilation rewrote the saved raw profile")
			}
		})
	}
}

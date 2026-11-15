//go:build with_awg && with_gvisor

package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/curve25519"
)

// Exercise exported profiles against the official AWG implementation, not the
// client's own fork. Everything runs on loopback and userspace stacks, without TUN.
func TestAWGProfileTCPUDPInterop(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprintf("AWG%d", version), func(t *testing.T) {
			stack, port, serverPublic, clientPrivate := officialAWGServer(t, version)
			tcp, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:8080"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tcp.Close() })
			go func() {
				c, err := tcp.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(c, c)
			}()
			udp, err := stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			go func() {
				var b [2048]byte
				for {
					n, addr, err := udp.ReadFrom(b[:])
					if err != nil {
						return
					}
					if _, err := udp.WriteTo(b[:n], addr); err != nil {
						return
					}
				}
			}()
			profile := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.77.0.2/32
MTU = 1280
Jc = 2
Jmin = 40
Jmax = 60
S1 = 20
S2 = 30
S3 = 12
S4 = 12
H1 = 1001-1010
H2 = 2001-2010
H3 = 3001-3010
H4 = 4001-4010
%s
[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.77.0.0/24
`, clientPrivate, awg3Profile(version), serverPublic, port)
			cfg := &model.Config{Connections: []model.Connection{{ID: "awg", Type: model.ConnAmneziaWG, AmneziaWG: profile}}}
			cfg.Defaults()
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			raw, err := compile.ConnectionValidationConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var e engine.Engine
			t.Cleanup(func() { e.Close() })
			if _, err := e.Apply(raw); err != nil {
				t.Fatal(err)
			}
			out, ctx, ok := e.Outbound("awg")
			if !ok {
				t.Fatal("applied AWG endpoint is unavailable")
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr("10.77.0.1:8080"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			assertAWGEcho(t, c, bytes.Repeat([]byte("tcp-over-awg\x00"), 1024))
			pc, err := out.ListenPacket(ctx, M.ParseSocksaddr("10.77.0.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(10 * time.Second))
			for _, payload := range [][]byte{[]byte("udp-over-awg"), bytes.Repeat([]byte{0x71}, 1100)} {
				if _, err := pc.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 77, 0, 1), Port: 443}); err != nil {
					t.Fatal(err)
				}
				var b [2048]byte
				n, _, err := pc.ReadFrom(b[:])
				if err != nil || !bytes.Equal(b[:n], payload) {
					t.Fatalf("AWG UDP reply mismatch: bytes=%d err=%v", n, err)
				}
			}
		})
	}
}

func assertAWGEcho(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("AWG TCP reply differs from the application payload")
	}
}

func awg3Profile(version int) string {
	if version == 2 {
		return ""
	}
	return "HeaderProtectionKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)) + "\nContentPaddingAddition = 0-16\nRandomTrailers = true\n"
}

func officialAWGServer(t *testing.T, version int) (*netstack.Net, int, string, string) {
	t.Helper()
	serverKey := bytes.Repeat([]byte{1}, 32)
	clientKey := bytes.Repeat([]byte{2}, 32)
	serverPublic, err := curve25519.X25519(serverKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, err := curve25519.X25519(clientKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	d := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "test-awg: "))
	t.Cleanup(d.Close)
	extra := ""
	if version == 3 {
		extra = "header_protection_key=" + hex.EncodeToString(bytes.Repeat([]byte{5}, 32)) + "\ncontent_padding_addition=0-16\nrandom_trailers=1\n"
	}
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\njc=2\njmin=40\njmax=60\ns1=20\ns2=30\ns3=12\ns4=12\nh1=1001-1010\nh2=2001-2010\nh3=3001-3010\nh4=4001-4010\n%spublic_key=%s\nallowed_ip=10.77.0.2/32\n", hex.EncodeToString(serverKey), extra, hex.EncodeToString(clientPublic))
	if err := d.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	state, err := d.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(state, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(value)
			if err != nil || port == 0 {
				t.Fatalf("invalid AWG listen port: %q", value)
			}
			return stack, port, base64.StdEncoding.EncodeToString(serverPublic), base64.StdEncoding.EncodeToString(clientKey)
		}
	}
	t.Fatal("official AWG server did not expose its UDP port")
	return nil, 0, "", ""
}

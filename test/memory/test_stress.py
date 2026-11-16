"""Behavioral coverage for the continuous memory stress gate."""
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from unittest.mock import patch
import unittest

import scenario
import stress

LIMIT = 384 * 1024 * 1024
PROFILE = "[Interface]\nMTU = 1400\nS2 = 8\n[Peer]\n"


def live_state(now, verified=1024, seq=1):
    return {
        "streams": 32,
        "live": 32,
        "verified": [verified] * 32,
        "last": [now] * 32,
        "published_at": now,
        "seq": seq,
        "errors": [],
    }

def counted(now, base, total):
    state = live_state(now, verified=base)
    state["verified"] = [base + 1] * stress.STREAMS
    state["verified"][0] = base + total - (stress.STREAMS - 1)
    return state


def heavy_stats(wg1=32, wg2=0, extra=None):
    rows = [{"tag": "wg1", "active": wg1}, {"tag": "wg2", "active": wg2}]
    if extra:
        rows.append(extra)
    return {"outbounds": rows}


class Proc:
    def __init__(self, pid=7, code=None, steps=None):
        self.pid = pid
        self.returncode = code
        self.killed = 0
        self.steps = list(steps or [])

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.steps:
            step = self.steps.pop(0)
            if step == "timeout":
                raise subprocess.TimeoutExpired("stress", timeout)
            self.returncode = step
            return step
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self):
        self.killed += 1
        self.returncode = -9


class Echo:
    def __init__(self, limit=3, corrupt=False):
        self.limit = limit
        self.corrupt = corrupt
        self.outbound = b""
        self.sent = 0
        self.closed = False

    def send(self, data):
        if self.limit == 0:
            raise BlockingIOError()
        take = data[:self.limit]
        self.outbound += take
        self.sent += len(take)
        return len(take)

    def recv(self, _size):
        if not self.outbound:
            raise BlockingIOError()
        chunk = self.outbound
        self.outbound = b""
        if self.corrupt and chunk:
            chunk = bytes([chunk[0] ^ 0xFF]) + chunk[1:]
            self.corrupt = False
        return chunk

    def close(self):
        self.closed = True


class Sock:
    def __init__(self):
        self.blocking = True
        self.nodelay = None
        self.closed = False

    def setblocking(self, value):
        self.blocking = value

    def setsockopt(self, _level, _opt, value):
        self.nodelay = value

    def close(self):
        self.closed = True


def clock():
    state = {"ms": 0}
    intervals = []

    def monotonic():
        return state["ms"] / 1000.0

    def sleep(interval):
        intervals.append(interval)
        state["ms"] += int(round(interval * 1000))

    return monotonic, sleep, intervals


class StressTests(unittest.TestCase):
    def test_partial_echo_is_verified_without_a_full_payload(self):
        state = {"index": 0, "pending": b"", "verified": 0, "last": 0.0, "live": True}
        sock = Echo(limit=3)
        self.assertEqual(stress.write_ready(state, sock), 3)
        self.assertEqual(state["pending"], stress.PAGES[0][3:])
        self.assertEqual(stress.read_ready(state, sock, 9), 3)
        self.assertEqual(state["verified"], 3)
        self.assertEqual(state["last"], 9)
        stress.write_ready(state, sock)
        stress.read_ready(state, sock, 10)
        self.assertEqual(state["verified"], 6)
        self.assertEqual(sock.sent, 6)
        self.assertEqual(state["pending"], stress.PAGES[0][6:])

    def test_corrupted_echo_fails_and_keeps_the_unsent_tail(self):
        state = {"index": 1, "pending": b"", "verified": 0, "last": 0.0, "live": True}
        sock = Echo(limit=5, corrupt=True)
        stress.write_ready(state, sock)
        with self.assertRaisesRegex(stress.StressError, "payload mismatch"):
            stress.read_ready(state, sock, 4)
        self.assertEqual(state["pending"], stress.PAGES[1][5:])
        self.assertEqual(state["verified"], 0)
        self.assertEqual(state["last"], 0.0)

    def test_blocked_send_does_not_drop_or_refresh_progress(self):
        state = {"index": 0, "pending": b"abc", "verified": 8, "last": 2.0, "live": True}
        sock = Echo(limit=0)
        self.assertEqual(stress.write_ready(state, sock), 0)
        self.assertEqual(stress.read_ready(state, sock, 99), 0)
        self.assertEqual(state["pending"], b"abc")
        self.assertEqual(state["last"], 2.0)


    def test_payload_mismatch_is_rejected_on_aligned_and_wrapped_spans(self):
        page = stress.build_page(3, 8)
        wrapped = page[6:] + page[:2]
        self.assertEqual(stress.verify_span(page, 6, wrapped), 4)
        bad = wrapped[:3] + bytes([wrapped[3] ^ 1])
        with self.assertRaisesRegex(stress.StressError, "payload mismatch"):
            stress.verify_span(page, 6, bad)
        aligned = bytearray(stress.PAGES[0][:80])
        aligned[40] ^= 0xFF
        with self.assertRaisesRegex(stress.StressError, "payload mismatch"):
            stress.verify_span(stress.PAGES[0], 0, bytes(aligned))
        with self.assertRaisesRegex(stress.StressError, "empty echo"):
            stress.verify_span(page, 0, b"")
        with self.assertRaises(stress.StressError):
            stress.verify_span(page, -1, b"ab")

    def test_closed_echo_is_not_reported_as_a_payload_mismatch(self):
        sock = Echo()
        sock.recv = lambda _size: b""
        state = {"index": 0, "verified": 0}
        with self.assertRaisesRegex(stress.StressError, "echo closed"):
            stress.read_ready(state, sock, 1)

    def test_ready_sockets_transfer_independently(self):
        socks, lookup = [], {}
        for index in (0, 1):
            sock = Echo(limit=4)
            lookup[sock] = {"index": index, "pending": b"", "verified": 0, "last": 0.0, "live": True}
            socks.append(sock)
        stress.pump_all(socks, lookup, 3, lambda r, w, e, timeout: (list(r), list(w), []))
        self.assertEqual([lookup[sock]["verified"] for sock in socks], [4, 4])
        self.assertEqual(lookup[socks[0]]["pending"], stress.PAGES[0][4:])
        self.assertEqual(lookup[socks[1]]["pending"], stress.PAGES[1][4:])

    def test_socket_exception_stops_before_another_write(self):
        sock = Echo()
        state = {"index": 0, "pending": b"", "verified": 0, "last": 0.0, "live": True}
        with self.assertRaisesRegex(stress.StressError, "socket exception"):
            stress.pump_all([sock], {sock: state}, 1, lambda r, w, e, timeout: ([], [], [sock]))
        self.assertEqual(sock.sent, 0)
        with self.assertRaises(stress.StressError):
            stress.pump_all([], {}, 1, lambda r, w, e, timeout: ([], [], []))

    def test_historical_readiness_and_stale_publication_are_not_progress(self):
        now = 20.0
        historical = live_state(now, verified=100000)
        historical["last"] = [now - 5] * 32
        self.assertFalse(stress.ready_snapshot(historical, now))
        with self.assertRaisesRegex(stress.StressError, "not progressing"):
            stress.assert_progress(historical, now)
        stale = live_state(now)
        stale["published_at"] = now - 2.001
        self.assertFalse(stress.ready_snapshot(stale, now))
        with self.assertRaisesRegex(stress.StressError, "stale traffic publication"):
            stress.assert_progress(stale, now)
        fresh = live_state(now - 2.0)
        fresh["published_at"] = now - 2.0
        self.assertTrue(stress.assert_progress(fresh, now))
        future = live_state(now)
        future["published_at"] = now + 1.001
        with self.assertRaisesRegex(stress.StressError, "stale traffic publication"):
            stress.assert_progress(future, now)

    def test_fresh_publication_can_repeat_but_cannot_regress_or_freeze(self):
        now = 10.0
        state = live_state(now, seq=4)
        self.assertEqual(stress.load_observation(state, now, None), 4)
        self.assertEqual(stress.load_observation(state, now + 0.2, 4), 4)
        with self.assertRaisesRegex(stress.StressError, "sequence"):
            stress.load_observation(state, now, 5)
        with self.assertRaisesRegex(stress.StressError, "stale"):
            stress.load_observation(state, now + 2.001, 4)
        state["errors"] = ["payload mismatch"]
        with self.assertRaises(stress.FatalStress):
            stress.load_observation(state, now, None)
        self.assertTrue(stress.stream_progressing(1, now, now))
        self.assertFalse(stress.stream_progressing(0, now, now))
        self.assertFalse(stress.stream_progressing(True, now, now))
        self.assertFalse(stress.stream_progressing(5, now + 1, now))

    def test_publication_sequence_accepts_zero_and_rejects_invalid_counters(self):
        state = live_state(10.0, seq=0)
        self.assertEqual(stress.load_observation(state, 10.0, None), 0)
        for seq in (-1, True, 1.5, "1", None):
            with self.subTest(seq=seq), self.assertRaises(stress.StressError):
                stress.load_observation(dict(state, seq=seq), 10.0, None)

    def test_every_stream_must_advance_during_the_load_window(self):
        before = live_state(1, verified=10)
        flat = live_state(2, verified=11)
        flat["verified"][3] = 10
        with self.assertRaisesRegex(stress.StressError, "stream 3"):
            stress.require_advanced(before, flat)
        after = live_state(2, verified=11)
        self.assertEqual(stress.require_advanced(before, after), 32)
        short = live_state(2)
        short["verified"] = [2] * 31
        with self.assertRaises(stress.StressError):
            stress.require_advanced(before, short)

    def test_throughput_floor_is_decimal_megabits_over_the_actual_window(self):
        self.assertEqual(stress.require_throughput(187500000, 30), 50000000)
        with self.assertRaisesRegex(stress.StressError, "50 Mbps"):
            stress.require_throughput(187499999, 30)
        with self.assertRaisesRegex(stress.StressError, "50 Mbps"):
            stress.require_throughput(32, 30)
        self.assertEqual(stress.verified_bps(0, 30), 0)
        with self.assertRaisesRegex(stress.StressError, "50 Mbps"):
            stress.require_throughput(0, 30)
        for args in ((-1, 30), (100, 0), (True, 30), (100, True)):
            with self.subTest(args=args), self.assertRaises(stress.StressError):
                stress.verified_bps(*args)

    def test_phase_clock_skew_cannot_pass_49_9_megabits(self):
        phase = {"seconds": 30.0, "cpu_percent_of_quota": 12.5}
        before = live_state(0.0, verified=0)
        after = counted(30.09, 0, 187_686_375)
        result = {"phases": {"loaded": dict(phase)}}
        with self.assertRaisesRegex(stress.StressError, "50 Mbps"):
            stress.require_load_rate(result, before, after)
        self.assertEqual(result["phases"]["loaded"], phase)
        self.assertEqual(result["traffic"]["elapsed_seconds"], 30.09)
        self.assertEqual(result["traffic"]["verified_bytes"], 187_686_375)
        self.assertEqual(result["traffic"]["verified_bps"], 49_900_000)
        self.assertLess(result["traffic"]["verified_bps"], stress.MIN_BPS)

    def test_sufficient_load_over_a_shorter_counter_interval_passes(self):
        phase = {"seconds": 30.0, "cpu_percent_of_quota": 12.5}
        before = live_state(0.0, verified=10)
        after = counted(29.9, 10, 186_875_000)
        result = {"phases": {"loaded": dict(phase)}}
        traffic = stress.require_load_rate(result, before, after)
        self.assertEqual(result["phases"]["loaded"], phase)
        self.assertEqual(traffic["elapsed_seconds"], 29.9)
        self.assertEqual(traffic["verified_bytes"], 186_875_000)
        self.assertEqual(traffic["verified_bps"], 50_000_000)

    def test_rate_uses_elapsed_time_not_the_monotonic_clock_origin(self):
        before = live_state(4096.0, verified=10)
        after = counted(4126.0, 10, 187_500_000)
        result = {"phases": {"loaded": {"seconds": 30.0}}}
        traffic = stress.require_load_rate(result, before, after)
        self.assertEqual(traffic["elapsed_seconds"], 30.0)
        self.assertEqual(traffic["verified_bps"], 50_000_000)

    def test_counter_interval_rejects_invalid_and_nonincreasing_timestamps(self):
        before = live_state(10.0, verified=0)
        advanced = counted(40.0, 0, 32)
        result = {"phases": {"loaded": {"seconds": 30}}, "traffic": {"kept": True}}
        for stamp in (None, True, False, "40", float("nan"), float("inf"), float("-inf"), 10.0, 10, 9.0):
            bad = counted(40.0, 0, 32)
            bad["published_at"] = stamp
            with self.subTest(stamp=stamp), self.assertRaisesRegex(stress.StressError, "invalid throughput window"):
                stress.require_load_rate(result, before, bad)
        missing = counted(40.0, 0, 32)
        del missing["published_at"]
        with self.assertRaisesRegex(stress.StressError, "invalid throughput window"):
            stress.require_load_rate(result, before, missing)
        early = live_state(10.0, verified=0)
        early["published_at"] = float("nan")
        with self.assertRaisesRegex(stress.StressError, "invalid throughput window"):
            stress.require_load_rate(result, early, advanced)
        for broken in (None, [], "snapshot"):
            with self.subTest(broken=broken):
                with self.assertRaisesRegex(stress.StressError, "invalid throughput window"):
                    stress.require_load_rate(result, broken, advanced)
                with self.assertRaisesRegex(stress.StressError, "invalid throughput window"):
                    stress.require_load_rate(result, before, broken)
        flat = live_state(40.0, verified=1)
        flat["verified"][4] = 0
        with self.assertRaisesRegex(stress.StressError, "stream 4"):
            stress.require_load_rate(result, before, flat)
        self.assertEqual(result["traffic"], {"kept": True})
        self.assertEqual(result["phases"]["loaded"]["seconds"], 30)

    def test_rss_ceiling_uses_the_kernel_high_water_mark(self):
        under = {"rss_bytes": LIMIT - 1, "hwm_bytes": LIMIT - 1}
        self.assertFalse(stress.exceeds_rss(under))
        self.assertTrue(stress.exceeds_rss({"rss_bytes": LIMIT, "hwm_bytes": LIMIT}))
        self.assertTrue(stress.exceeds_rss({"rss_bytes": 1024, "hwm_bytes": LIMIT}))
        self.assertTrue(stress.exceeds_rss({"rss_bytes": LIMIT, "hwm_bytes": 1024}))
        with self.assertRaises(stress.StressError):
            stress.exceeds_rss({"rss_bytes": 1024})
        with self.assertRaises(stress.StressError):
            stress.exceeds_rss({"rss_bytes": True, "hwm_bytes": 1})

    def test_ceiling_records_the_breach_and_stops_sampling(self):
        calls, samples = [], []
        clock_state = {"now": 0}

        def observe():
            calls.append("observe")

        def read_sample():
            calls.append("read")
            if calls.count("read") == 2:
                return {"rss_bytes": 10, "anon_bytes": 10, "hwm_bytes": LIMIT}
            return {"rss_bytes": 10, "anon_bytes": 10, "hwm_bytes": 20}

        def monotonic():
            return clock_state["now"]

        def sleep(interval):
            clock_state["now"] += interval

        with self.assertRaises(stress.Ceiling):
            stress.measure_into(samples, 30, read_sample, observe, sleep, monotonic)
        self.assertEqual(calls.count("read"), 2)
        self.assertEqual(calls.count("observe"), 2)
        self.assertEqual(samples[-1]["hwm_bytes"], LIMIT)

    def test_phase_finishes_at_the_deadline_with_a_terminal_sample(self):
        monotonic, sleep, _intervals = clock()
        samples = []

        def advance(duration):
            self.assertGreater(duration, 0, "measurement must finish instead of spinning at its deadline")
            sleep(duration)

        elapsed = stress.measure_into(samples, 0.4, sample, lambda: None, advance, monotonic)
        self.assertEqual(elapsed, 0.4)
        self.assertEqual([row["time"] for row in samples], [0, 0.2, 0.4])

    def test_terminal_sample_detects_a_spike_in_the_last_sleep(self):
        monotonic, sleep, _intervals = clock()
        samples, observations = [], []

        def memory():
            row = sample()
            if monotonic() >= 0.4:
                row["hwm_bytes"] = LIMIT
            return row

        with self.assertRaises(stress.Ceiling):
            stress.measure_into(samples, 0.4, memory, lambda: observations.append(monotonic()), sleep, monotonic)
        self.assertEqual(observations, [0, 0.2, 0.4])
        self.assertEqual(samples[-1]["time"], 0.4)
        self.assertEqual(samples[-1]["hwm_bytes"], LIMIT)

    def test_terminal_observation_detects_sessions_and_daemon_exit(self):
        for violation in ("sessions", "exit"):
            with self.subTest(violation=violation):
                monotonic, sleep, _intervals = clock()
                daemon, client = Proc(), Proc(code=0)

                def observe():
                    terminal = monotonic() >= 0.4
                    if terminal and violation == "exit":
                        daemon.returncode = 1
                    stress.drain_observation(daemon, daemon.pid, client, int(terminal and violation == "sessions"), 0)

                with self.assertRaises((stress.StressError, stress.FatalStress)):
                    stress.measure_into([], 0.4, sample, observe, sleep, monotonic)

    def test_procfs_hwm_and_cpu_are_fail_closed(self):
        text = "VmRSS:\t2048 kB\nRssAnon:\t1024 kB\nVmHWM:\t4096 kB\n"
        row = stress.read_memory(text)
        self.assertEqual(row["rss_bytes"], 2048 * 1024)
        self.assertEqual(row["hwm_bytes"], 4096 * 1024)
        with self.assertRaises(stress.StressError):
            stress.read_memory("VmRSS:\t2048 kB\nRssAnon:\t1024 kB\n")
        with self.assertRaises(stress.StressError):
            stress.parse_hwm("VmHWM: 1 MB\n")
        with self.assertRaises(stress.StressError):
            stress.read_memory("VmRSS:\t2048 kB\nRssAnon:\t1024 kB\nVmHWM:\t512 kB\n")
        stat = "42 (ke en) R " + " ".join(["0"] * 10) + " 15 25\n"
        self.assertEqual(stress.parse_cpu_ticks(stat), 40)
        for bad in ("42 ke en R 1\n", "42 (ke en) R 1 2\n", "42 (ke en) R " + " ".join(["x"] * 13)):
            with self.subTest(bad=bad), self.assertRaises(stress.StressError):
                stress.parse_cpu_ticks(bad)

    def test_phase_summary_keeps_hwm_above_sampled_rss(self):
        samples = [
            {"rss_bytes": 100, "anon_bytes": 50, "hwm_bytes": 500},
            {"rss_bytes": 120, "anon_bytes": 60, "hwm_bytes": 900},
            {"rss_bytes": 80, "anon_bytes": 40, "hwm_bytes": 900},
        ]
        summary = stress.summarize(samples, 30, 100, 100)
        self.assertEqual(summary["peak_rss_bytes"], 120)
        self.assertEqual(summary["hwm_bytes"], 900)
        self.assertEqual(summary["cpu_seconds"], 1)
        with self.assertRaises(stress.StressError):
            stress.summarize([], 30, 0, 100)

    def test_session_gates_reject_partial_drain_and_a_loaded_idle_tunnel(self):
        self.assertTrue(stress.counts_idle(0, 0))
        self.assertFalse(stress.counts_idle(1, 0))
        self.assertFalse(stress.counts_idle(0, 1))
        with self.assertRaises(stress.FatalStress):
            stress.counts_idle(True, 0)
        with self.assertRaisesRegex(stress.StressError, "TCP sessions remain"):
            stress.require_idle_counts(0, 1)
        self.assertTrue(stress.require_heavy_tunnel(heavy_stats()))
        with self.assertRaisesRegex(stress.StressError, "32 sessions"):
            stress.require_heavy_tunnel(heavy_stats(wg1=31))
        with self.assertRaisesRegex(stress.StressError, "idle"):
            stress.require_heavy_tunnel(heavy_stats(wg2=1))
        with self.assertRaisesRegex(stress.StressError, "idle"):
            stress.require_heavy_tunnel(heavy_stats(extra={"tag": "direct", "active": 1}))
        with self.assertRaises(stress.StressError):
            stress.active_rows({"outbounds": [{"tag": "wg1", "active": True}]})
        with self.assertRaises(stress.StressError):
            stress.server_tcp({"tcp_connections": -1})
        self.assertEqual(stress.server_tcp({"tcp_connections": 0}), 0)
        self.assertEqual(stress.daemon_active(heavy_stats()), 32)

    def test_same_pid_and_reaped_child_are_required(self):
        live = Proc(pid=7)
        self.assertTrue(stress.require_live(live, 7))
        with self.assertRaises(stress.FatalStress):
            stress.require_live(live, 8)
        with self.assertRaises(stress.FatalStress):
            stress.require_live(None, 7)
        with self.assertRaises(stress.FatalStress):
            stress.require_live(Proc(pid=7, code=1), 7)
        with self.assertRaisesRegex(stress.StressError, "still alive"):
            stress.require_reaped(live)
        self.assertTrue(stress.require_reaped(Proc(pid=9, code=0)))
        daemon = Proc(pid=7)
        self.assertTrue(stress.drain_observation(daemon, 7, Proc(code=0), 0, 0))
        with self.assertRaisesRegex(stress.StressError, "still alive"):
            stress.drain_observation(daemon, 7, live, 0, 0)
        with self.assertRaisesRegex(stress.StressError, "TCP sessions remain"):
            stress.drain_observation(daemon, 7, Proc(code=0), 1, 0)
        with self.assertRaises(stress.FatalStress):
            stress.zero_ready(Proc(pid=7, code=1), 7, 0, 0)
        self.assertFalse(stress.zero_ready(daemon, 7, 0, 2))

    def test_environ_limit_is_only_on_the_measured_daemon(self):
        daemon_blob = b"GOMEMLIMIT=320MiB\0GOGC=100\0GOMAXPROCS=2\0"
        server_blob = b"GOGC=100\0GOMEMLIMIT=off\0GOMAXPROCS=2\0"
        self.assertTrue(stress.require_daemon_environ(stress.parse_environ(daemon_blob)))
        self.assertTrue(stress.require_server_environ(stress.parse_environ(server_blob)))
        with self.assertRaisesRegex(stress.StressError, "320MiB"):
            stress.require_daemon_environ({"GOMEMLIMIT": "off", "GOGC": "100", "GOMAXPROCS": "2"})
        with self.assertRaisesRegex(stress.StressError, "GOGC"):
            stress.require_daemon_environ({"GOMEMLIMIT": "320MiB", "GOGC": "100", "GOMAXPROCS": "3"})
        with self.assertRaisesRegex(stress.StressError, "off"):
            stress.require_server_environ({"GOMEMLIMIT": "320MiB"})
        with self.assertRaises(stress.StressError):
            stress.require_server_environ({})
        with self.assertRaises(stress.StressError):
            stress.parse_environ(b"NOEQUALS\0")
        with self.assertRaises(stress.StressError):
            stress.parse_environ("GOMEMLIMIT=320MiB")
        files = {
            "/proc/7/environ": daemon_blob,
            "/proc/8/environ": server_blob,
        }
        binaries = {"/proc/7/exe": "/binaries/candidate", "/proc/8/exe": "/binaries/sbserver"}
        real_readlink = stress.os.readlink

        def read_executable(path, *args, **kwargs):
            if str(path) in binaries:
                return binaries[str(path)]
            return real_readlink(path, *args, **kwargs)

        with patch.object(stress.Path, "read_bytes", lambda path: files[str(path)]), patch.object(stress.os, "readlink", read_executable):
            identity = stress.capture_identity(Proc(7), Proc(8), "/binaries/candidate", "/binaries/sbserver")
            self.assertEqual(identity["pid"], 7)
            self.assertEqual(identity["environ"]["keenproxy"]["GOMEMLIMIT"], "320MiB")
            self.assertEqual(identity["environ"]["sbserver"]["GOMEMLIMIT"], "off")
            files["/proc/8/environ"] = daemon_blob
            with self.assertRaisesRegex(stress.StressError, "off"):
                stress.capture_identity(Proc(7), Proc(8), "/binaries/candidate", "/binaries/sbserver")
            files["/proc/8/environ"] = server_blob
            binaries["/proc/7/exe"] = "/usr/bin/env"
            with self.assertRaisesRegex(stress.StressError, "executable"):
                stress.capture_identity(Proc(7), Proc(8), "/binaries/candidate", "/binaries/sbserver")

    def test_launch_prefix_and_transport_stay_on_the_awg_pair(self):
        self.assertEqual(
            stress.prefix_daemon("keenproxy", ("/bin/keenproxy", "-config", "c")),
            ("/usr/bin/env", "GOMEMLIMIT=320MiB", "/bin/keenproxy", "-config", "c"))
        self.assertEqual(stress.prefix_daemon("sbserver", ("/bin/sbserver",)), ("/bin/sbserver",))
        config = {"connections": [
            {"type": "amneziawg", "amneziawg": PROFILE},
            {"type": "wireguard", "wireguard": {"mtu": 1400}},
        ]}
        server = {"endpoints": [{"s1": 8, "s2": 8, "mtu": 1400}, {"mtu": 1400}]}
        stress.apply_transport(config, server)
        self.assertEqual(server["endpoints"][0]["s4"], 12)
        self.assertEqual(server["endpoints"][0]["mtu"], 1280)
        self.assertEqual(server["endpoints"][1]["mtu"], 1280)
        self.assertNotIn("s4", server["endpoints"][1])
        self.assertEqual(config["connections"][0]["amneziawg"].count("S4 = 12\n"), 1)
        self.assertEqual(config["connections"][0]["amneziawg"].count("MTU = 1280\n"), 1)
        self.assertNotIn("MTU = 1400\n", config["connections"][0]["amneziawg"])
        self.assertEqual(config["connections"][1]["wireguard"]["mtu"], 1280)
        with self.assertRaises(stress.StressError):
            stress.apply_transport({"connections": config["connections"][:1]}, server)
        drifted = {"endpoints": [{"s1": 0, "s2": 8}, {"mtu": 1400}]}
        with self.assertRaisesRegex(stress.StressError, "drifted"):
            stress.apply_transport(config, drifted)
        with self.assertRaises(stress.StressError):
            stress.rewrite_profile(PROFILE.replace("MTU = 1400\n", ""))
        with self.assertRaises(stress.StressError):
            stress.rewrite_profile(PROFILE + "S4 = 1\n")

    def test_ready_waits_for_progress_and_rejects_a_dead_client(self):
        now = 5.0
        daemon, client = Proc(pid=4), Proc(pid=5)
        self.assertFalse(stress.service_ready(client, daemon, 4, None, now, None))
        historical = live_state(now)
        historical["last"] = [now - 5] * 32
        self.assertFalse(stress.service_ready(client, daemon, 4, historical, now, None))
        self.assertTrue(stress.service_ready(client, daemon, 4, live_state(now), now, heavy_stats()))
        with self.assertRaises(stress.FatalStress):
            stress.service_ready(Proc(pid=5, code=1), daemon, 4, live_state(now), now, heavy_stats())
        failed = live_state(now)
        failed["errors"] = ["payload mismatch"]
        with self.assertRaises(stress.FatalStress):
            stress.service_ready(client, daemon, 4, failed, now, heavy_stats())
        with self.assertRaises(stress.StressError):
            stress.service_ready(client, daemon, 4, live_state(now), now, heavy_stats(wg2=1))

    def test_client_loop_verifies_partial_writes_and_fails_closed(self):
        published = []
        stop = threading.Event()
        pumps = {"n": 0}
        sock = Echo(limit=3)
        lookup, ordered = stress.bind_states([sock])

        def select_fn(readable, writable, _exceptional, _timeout):
            pumps["n"] += 1
            if pumps["n"] == 3:
                stop.set()
            return list(readable), list(writable), []

        code = stress.run_client(
            [sock], lookup, ordered, stop, Absent(), published.append,
            ticking(), select_fn, 10)
        self.assertEqual(code, 0)
        self.assertGreater(ordered[0]["verified"], 0)
        self.assertGreater(published[-1]["seq"], published[0]["seq"])
        self.assertFalse(published[-1]["errors"])

        bad = Echo(limit=3, corrupt=True)
        lookup, ordered = stress.bind_states([bad])
        published = []
        code = stress.run_client(
            [bad], lookup, ordered, threading.Event(), Absent(), published.append,
            lambda: 1.0, lambda r, w, e, timeout: (list(r), list(w), []), 10)
        self.assertEqual(code, 1)
        self.assertIn("payload mismatch", published[-1]["errors"][0])

    def test_stop_beats_the_deadline_and_a_hung_client_fails(self):
        stop = threading.Event()
        stop.set()
        sock = Echo()
        lookup, ordered = stress.bind_states([sock])
        code = stress.run_client(
            [sock], lookup, ordered, stop, Absent(), lambda _state: None,
            lambda: 100.0, lambda r, w, e, timeout: ([], [], []), 0)
        self.assertEqual(code, 0)
        hung = threading.Event()
        code = stress.run_client(
            [sock], lookup, ordered, hung, Absent(), lambda _state: None,
            lambda: 5.0, lambda r, w, e, timeout: ([], [], []), 1)
        self.assertEqual(code, 1)
        sock.close = lambda: (_ for _ in ()).throw(OSError("close failed"))
        stopped = threading.Event()
        stopped.set()
        self.assertEqual(stress.run_client(
            [sock], lookup, ordered, stopped, Absent(), lambda _state: None,
            lambda: 1.0, lambda r, w, e, timeout: ([], [], []), 10), 1)

    def test_open_streams_configures_sockets_and_closes_them_on_failure(self):
        created = []

        def connect(_address, _timeout):
            if created:
                raise OSError("refused")
            sock = Sock()
            created.append(sock)
            return sock

        with self.assertRaises(OSError):
            stress.open_streams("127.0.0.1", 9, 2, 1, connect=connect)
        self.assertTrue(created[0].closed)
        created.clear()

        def connect_ok(_address, _timeout):
            sock = Sock()
            created.append(sock)
            return sock

        sockets = stress.open_streams("127.0.0.1", 9, 2, 1, connect=connect_ok)
        self.assertEqual([sock.blocking for sock in sockets], [False, False])
        self.assertEqual([sock.nodelay for sock in sockets], [1, 1])
        self.assertFalse(any(sock.closed for sock in sockets))
        broken = Sock()
        broken.setblocking = lambda _value: (_ for _ in ()).throw(OSError("configure failed"))
        with self.assertRaisesRegex(OSError, "configure failed"):
            stress.open_streams("127.0.0.1", 9, 1, 1, connect=lambda *_args: broken)
        self.assertTrue(broken.closed)

    def test_bounded_stop_kills_a_stuck_client_and_detaches_a_clean_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            stop = Path(tmp) / "stop"
            stuck = Proc(steps=["timeout", "timeout"])
            with self.assertRaises(subprocess.TimeoutExpired):
                stress.stop_owned(stuck, stop, wait_seconds=10, kill_seconds=5)
            self.assertEqual(stuck.killed, 1)
            self.assertTrue(stop.is_file())
            late = Proc(steps=["timeout", 0])
            with self.assertRaisesRegex(stress.StressError, "timed out"):
                stress.stop_owned(late, stop)
            self.assertEqual(late.killed, 1)
            failed = Proc(steps=[1])
            with self.assertRaisesRegex(stress.StressError, "failed"):
                stress.stop_owned(failed, stop)
            clean = Proc()
            fixture = type("F", (), {"processes": [("stress", clean), ("keenproxy", Proc(pid=3))]})()
            state = {"client": (clean, Path(tmp) / "state", stop)}
            stress.release_client(fixture, state)
            self.assertEqual([label for label, _proc in fixture.processes], ["keenproxy"])
            self.assertIsNone(state["client"])
            self.assertEqual(state["stopped"].poll(), 0)

    def test_stop_failure_retains_ownership_until_cleanup_reaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process = Proc()
            fixture = type("F", (), {"processes": [("stress", process)]})()
            state = {"client": (process, root / "state", root / "missing" / "stop")}
            # Simulate a kill syscall failure: the client must remain owned.
            with patch.object(process, "kill", side_effect=OSError("kill denied")):
                with self.assertRaisesRegex(OSError, "kill denied"):
                    stress.release_client(fixture, state)
            self.assertIs(state["client"][0], process)
            self.assertEqual(fixture.processes, [("stress", process)])
            with self.assertRaises(FileNotFoundError):
                stress.release_client(fixture, state)
            self.assertIsNone(state["client"])
            self.assertEqual(process.poll(), -9)
            self.assertEqual(fixture.processes, [])

    def test_failure_preserves_artifacts_and_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "stress.json"
            directory = root / "ipc"
            directory.mkdir()
            (directory / "keenproxy.log").write_text("log")
            cleanup = scenario.Cleanup()
            stress.install_preserve(cleanup, directory, output, {})
            calls = []
            fixture = type("F", (), {
                "stats_samples": [{"saved": True}],
                "processes": [],
                "failure_snapshot": lambda self: calls.append("diag"),
            })()
            with self.assertRaisesRegex(stress.StressError, "stall"):
                stress.guarded(directory, output, cleanup, fixture, {}, lambda _result: (_ for _ in ()).throw(stress.StressError("stall")))
            report = json.loads(output.read_text())
            self.assertFalse(report["success"])
            self.assertIn("stall", report["error"])
            artifacts = output.with_suffix(".artifacts")
            self.assertTrue((artifacts / "failure.log").is_file())
            self.assertTrue((artifacts / "keenproxy.log").is_file())
            self.assertTrue((artifacts / "stats.json").is_file())
            self.assertFalse(directory.exists())
            self.assertEqual(calls, ["diag"])


    def test_failed_stop_skips_diagnostics_and_keeps_the_original_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "stress.json"
            directory = root / "ipc"
            directory.mkdir()
            cleanup = scenario.Cleanup()
            stress.install_preserve(cleanup, directory, output, {})
            calls = []
            stuck = Proc(steps=["timeout"])
            cleanup.add(lambda: Proc.kill(stuck))
            fixture = type("F", (), {
                "stats_samples": [],
                "processes": [("stress", stuck)],
                "failure_snapshot": lambda self: calls.append("diag"),
            })()
            run_state = {"client": (stuck, root / "state.json", root / "stop")}

            def stall(_result):
                raise stress.StressError("stall")

            with patch.object(stuck, "kill", side_effect=OSError("kill denied")):
                with self.assertRaisesRegex(stress.StressError, "stall"):
                    stress.guarded(directory, output, cleanup, fixture, run_state, stall)
            report = json.loads(output.read_text())
            self.assertEqual(calls, [])
            self.assertEqual(stuck.killed, 1)
            self.assertIn("stall", report["error"])
            self.assertIn("kill denied", report["stop_error"])
            self.assertFalse(report["success"])

    def test_copy_failure_retains_the_ipc_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "stress.json"
            directory = root / "ipc"
            directory.mkdir()
            (directory / "failure-source.log").write_text("evidence")
            cleanup = scenario.Cleanup()
            stress.install_preserve(cleanup, directory, output, {})
            fixture = type("F", (), {
                "stats_samples": [],
                "processes": [],
                "failure_snapshot": lambda self: None,
            })()
            original = stress.shutil.copytree

            def fail_copy(_source, _dest):
                raise OSError("artifact destination unavailable")

            stress.shutil.copytree = fail_copy
            try:
                with self.assertRaisesRegex(stress.StressError, "stall"):
                    def stall(_result):
                        raise stress.StressError("stall")

                    stress.guarded(directory, output, cleanup, fixture, {}, stall)
            finally:
                stress.shutil.copytree = original
            report = json.loads(output.read_text())
            self.assertFalse(report["success"])
            self.assertEqual(report["retained_artifacts"], str(directory))
            self.assertIn("artifact destination unavailable", report["cleanup_error"])
            self.assertTrue((directory / "failure.log").is_file())
            self.assertTrue(directory.exists())

    def test_cleanup_failure_after_success_is_still_a_failed_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "stress.json"
            directory = root / "ipc"
            directory.mkdir()
            cleanup = scenario.Cleanup()
            stress.install_preserve(cleanup, directory, output, {})

            def fail():
                raise RuntimeError("owned resource remains")

            cleanup.add(fail)
            fixture = type("F", (), {"stats_samples": [], "processes": [], "failure_snapshot": lambda self: None})()
            with self.assertRaisesRegex(stress.StressError, "owned resource remains"):
                stress.guarded(directory, output, cleanup, fixture, {}, lambda result: result.update({"phases": {"idle": {}}}))
            report = json.loads(output.read_text())
            self.assertFalse(report["success"])
            self.assertIn("owned resource remains", report["cleanup_error"])
            self.assertFalse((output.with_suffix(".artifacts") / "failure.log").exists())
            self.assertFalse(directory.exists())
            self.assertNotIn("retained_artifacts", report)

    def test_unreadable_publication_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("{")
            with self.assertRaises(stress.FatalStress):
                stress.read_state(path)
            path.write_text("[]\n")
            with self.assertRaises(stress.FatalStress):
                stress.read_state(path)
            path.write_text('{"verified": []}\n')
            self.assertEqual(stress.read_state(path)["verified"], [])
            missing = Path(tmp) / "missing.json"
        with self.assertRaises(stress.FatalStress):
            stress.read_state(missing)

    def test_persistence_failures_cannot_skip_stop_or_cleanup(self):
        for broken in ("failure.log", "stats.json.tmp", "stress.json.tmp"):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                directory = root / "ipc"
                directory.mkdir()
                output = root / "stress.json"
                process = Proc()
                cleanup = scenario.Cleanup()
                calls = []
                cleanup.add(lambda: calls.append("cleanup"))
                fixture = type("F", (), {
                    "stats_samples": [],
                    "processes": [("stress", process)],
                    "failure_snapshot": lambda self: calls.append(("diag", process.poll())),
                })()
                state = {"client": (process, root / "state", root / "stop")}
                write_text = Path.write_text

                def write(path, *args, **kwargs):
                    if path.name == broken:
                        self.assertIsNotNone(process.poll())
                        raise OSError("disk unavailable")
                    return write_text(path, *args, **kwargs)

                def fail(_result):
                    raise stress.StressError("original failure")

                with patch.object(Path, "write_text", write):
                    with self.assertRaisesRegex(stress.StressError, "original failure"):
                        stress.guarded(directory, output, cleanup, fixture, state, fail)
                self.assertIsNone(state["client"])
                self.assertEqual(calls, [("diag", 0), "cleanup"])
                if broken != "stress.json.tmp":
                    report = json.loads(output.read_text())
                    self.assertEqual(report["error"], "original failure")
                    key = "failure_log_error" if broken == "failure.log" else "stats_error"
                    self.assertIn("disk unavailable", report[key])

    def test_stats_and_result_failure_after_success_still_cleanup_and_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls = []
            cleanup = scenario.Cleanup()
            cleanup.add(lambda: calls.append("cleanup"))
            fixture = type("F", (), {"stats_samples": []})()
            with patch.object(stress.scenario, "save_json", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(stress.StressError, "disk full") as caught:
                    stress.guarded(root, root / "result", cleanup, fixture, {}, lambda _result: None)
            self.assertEqual(calls, ["cleanup"])
            self.assertIsInstance(caught.exception.__cause__, OSError)



def sample():
    return {"rss_bytes": 100, "anon_bytes": 40, "hwm_bytes": 200}


def ticking():
    state = {"now": 0.0}

    def monotonic():
        state["now"] += 0.05
        return state["now"]

    return monotonic


class Absent:
    def exists(self):
        return False


if __name__ == "__main__":
    unittest.main()

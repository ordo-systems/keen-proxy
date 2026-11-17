#!/usr/bin/env python3
"""Continuous AmneziaWG stress step for the memory gate.

One heavy AWG tunnel carries 32 independent TCP echoes. The second WG tunnel
stays idle. GOMEMLIMIT applies only to the measured keenproxy process. The
kernel high-water mark is the RSS ceiling so a 200ms sample cannot miss a spike.
No diagnostic HTTP, forced GC, or production runtime change is used.
"""
import argparse
import json
import math
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
import uuid

import scenario

STREAMS = 32
MTU = 1280
S4 = 12
IDLE_SECONDS = 5
LOAD_SECONDS = 30
DRAIN_SECONDS = 20
SAMPLE_INTERVAL = 0.2
FRESH_SECONDS = 2.0
READY_TIMEOUT = 20
DRAIN_WAIT = 20
STOP_TIMEOUT = 10
KILL_TIMEOUT = 5
CLIENT_DEADLINE = 90
PAGE_BYTES = 65536
HARD_RSS_BYTES = 384 * 1024 * 1024
MIN_BPS = 50 * 1_000_000
HEAVY = scenario.TAGS[0]
IDLE = scenario.TAGS[1]

SETTINGS = {
    "mtu": MTU,
    "s4": S4,
    "streams": STREAMS,
    "heavy_tunnel": HEAVY,
    "idle_tunnel": IDLE,
    "target": scenario.TARGETS[0],
    "idle_seconds": IDLE_SECONDS,
    "load_seconds": LOAD_SECONDS,
    "drain_seconds": DRAIN_SECONDS,
    "sample_seconds": SAMPLE_INTERVAL,
    "fresh_seconds": FRESH_SECONDS,
    "gomemlimit": "320MiB",
    "gogc": "100",
    "gomaxprocs": "2",
    "server_gomemlimit": "off",
}
LIMITS = {
    "rss_hard_bytes": HARD_RSS_BYTES,
    "soft_gomemlimit": "320MiB",
    "min_verified_bps": MIN_BPS,
    "streams": STREAMS,
}


class StressError(scenario.ScenarioError):
    pass


class FatalStress(RuntimeError):
    """Non-retryable failure. wait_for must not swallow it."""


class Ceiling(FatalStress):
    """Hard RSS gate. The caller stops the client before any diagnostic."""


def build_page(stream, size=PAGE_BYTES):
    """Each stream has its own repeating pattern so a swapped echo cannot pass."""
    return bytes((stream * 17 + index * 31 + 9) & 0xFF for index in range(size))


PAGES = tuple(build_page(index) for index in range(STREAMS))


def verify_span(page, offset, chunk):
    """Match echoed bytes at the read offset, independent of write boundaries."""
    if not chunk:
        raise StressError("empty echo")
    if type(offset) is not int or offset < 0 or not page:
        raise StressError("invalid payload offset")
    cursor = offset % len(page)
    rest = chunk
    while rest:
        take = min(len(rest), len(page) - cursor)
        if rest[:take] != page[cursor:cursor + take]:
            raise StressError("payload mismatch")
        rest = rest[take:]
        cursor = 0
    return len(chunk)


def write_ready(state, sock):
    pending = state["pending"] or PAGES[state["index"]]
    try:
        sent = sock.send(pending)
    except BlockingIOError:
        state["pending"] = pending
        return 0
    state["pending"] = pending[sent:]
    return sent


def read_ready(state, sock, now):
    try:
        chunk = sock.recv(65536)
    except BlockingIOError:
        return 0
    if not chunk:
        raise StressError("echo closed during transfer")
    count = verify_span(PAGES[state["index"]], state["verified"], chunk)
    state["verified"] += count
    state["last"] = now
    return count


def pump_all(sockets, lookup, now, select_fn):
    """Write and read whichever sockets are ready. Do not stop-and-wait."""
    if not sockets:
        raise StressError("no stress streams")
    readable, writable, exceptional = select_fn(sockets, sockets, sockets, 0.1)
    if exceptional:
        raise StressError("socket exception during transfer")
    for sock in writable:
        write_ready(lookup[sock], sock)
    for sock in readable:
        read_ready(lookup[sock], sock, now)


def publication(states, errors, now, seq):
    return {
        "streams": len(states),
        "live": sum(1 for state in states if state["live"]),
        "verified": [state["verified"] for state in states],
        "last": [state["last"] for state in states],
        "published_at": now,
        "seq": seq,
        "errors": list(errors),
    }


def stream_progressing(verified, stamp, now, freshness=FRESH_SECONDS):
    """Historical readiness is not progress. The latest verified byte must be recent."""
    if type(verified) is not int or verified <= 0:
        return False
    if type(stamp) not in (int, float) or type(now) not in (int, float):
        return False
    age = now - stamp
    return 0 <= age <= freshness


def assert_progress(state, now):
    """Validate the published boundary once; historical bytes are not progress."""
    if state.get("streams") != STREAMS or state.get("live") != STREAMS:
        raise StressError("lost live streams")
    published = state.get("published_at")
    if type(published) not in (int, float) or not -1 <= now - published <= FRESH_SECONDS:
        raise StressError("stale traffic publication")
    last, verified = state.get("last"), state.get("verified")
    if type(last) is not list or type(verified) is not list or len(last) != STREAMS or len(verified) != STREAMS:
        raise StressError("missing per-stream progress")
    for index in range(STREAMS):
        if not stream_progressing(verified[index], last[index], now):
            raise StressError("stream " + str(index) + " is not progressing")
    return True


def ready_snapshot(state, now):
    try:
        return assert_progress(state, now)
    except StressError:
        return False


def load_observation(state, now, previous):
    if state.get("errors"):
        raise FatalStress("transfer failed: " + repr(state["errors"]))
    assert_progress(state, now)
    seq = state.get("seq")
    if type(seq) is not int or seq < 0 or (previous is not None and seq < previous):
        raise StressError("traffic publication sequence regressed or is invalid")
    return seq


def verified_list(state):
    values = state.get("verified")
    if type(values) is not list or len(values) != STREAMS:
        raise StressError("missing load-window counters")
    return values


def require_advanced(before, after):
    """Every stream must move during the timed window, not only before it."""
    start, end = verified_list(before), verified_list(after)
    for index in range(STREAMS):
        if type(start[index]) is not int or type(end[index]) is not int or end[index] <= start[index]:
            raise StressError("stream " + str(index) + " did not advance during load")
    return sum(end) - sum(start)


def verified_bps(byte_count, elapsed):
    if type(byte_count) is not int or byte_count < 0 or type(elapsed) not in (int, float) or elapsed <= 0:
        raise StressError("invalid throughput window")
    return byte_count * 8 / elapsed


def require_throughput(byte_count, elapsed, minimum=MIN_BPS):
    """Decimal Mbps over the actual window. A no-op or token transfer must fail."""
    rate = verified_bps(byte_count, elapsed)
    if rate < minimum:
        raise StressError("verified echo below 50 Mbps")
    return rate


def traffic_report(verified_bytes, elapsed, state):
    return {
        "streams": STREAMS,
        "elapsed_seconds": elapsed,
        "verified_bytes": verified_bytes,
        "verified_bps": int(verified_bps(verified_bytes, elapsed)),
        "per_stream_verified": list(verified_list(state)),
        "progressing": STREAMS,
    }


def published_time(state):
    """Finite instant stamped on this counter snapshot."""
    if type(state) is not dict:
        raise StressError("invalid throughput window")
    value = state.get("published_at")
    if type(value) not in (int, float) or not math.isfinite(value):
        raise StressError("invalid throughput window")
    return value


def counter_window(before, after):
    """Verified-byte delta and the publication interval that owns those counters."""
    started, ended = published_time(before), published_time(after)
    if ended <= started:
        raise StressError("invalid throughput window")
    return require_advanced(before, after), ended - started


def require_load_rate(result, before, after):
    """Record and gate the load on the publication interval that owns the counters.

    result["phases"]["loaded"]["seconds"] is the memory and CPU sample clock.
    It is not the counter interval and must not rate these snapshots.
    """
    verified, elapsed = counter_window(before, after)
    result["traffic"] = traffic_report(verified, elapsed, after)
    require_throughput(verified, elapsed)
    return result["traffic"]


def parse_hwm(text):
    value = None
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "VmHWM:":
            continue
        if len(parts) != 3 or parts[2] != "kB" or not parts[1].isdigit():
            raise StressError("invalid procfs VmHWM: " + line)
        value = int(parts[1]) * 1024
    if value is None:
        raise StressError("missing procfs VmHWM")
    return value


def read_memory(text):
    row = scenario.parse_status(text)
    row["hwm_bytes"] = parse_hwm(text)
    if row["hwm_bytes"] < row["rss_bytes"]:
        raise StressError("VmHWM below current RSS")
    return row


def exceeds_rss(row, limit=HARD_RSS_BYTES):
    """VmHWM is the ceiling. Current RSS alone can miss a spike between samples."""
    rss, hwm = row.get("rss_bytes"), row.get("hwm_bytes")
    if type(rss) is not int or type(hwm) is not int:
        raise StressError("memory sample is missing RSS or VmHWM")
    return rss >= limit or hwm >= limit


def parse_cpu_ticks(text):
    head, separator, tail = text.rpartition(") ")
    if not head or separator != ") ":
        raise StressError("invalid procfs stat")
    parts = tail.split()
    if len(parts) < 13:
        raise StressError("invalid procfs stat")
    try:
        return int(parts[11]) + int(parts[12])
    except ValueError as exc:
        raise StressError("invalid procfs stat") from exc


def summarize(samples, elapsed, cpu_delta, ticks, cpus=2):
    if not samples:
        raise StressError("phase has no memory samples")
    cpu_seconds = cpu_delta / ticks
    return {
        "seconds": elapsed,
        "rss_bytes": int(statistics.median(sample["rss_bytes"] for sample in samples)),
        "anon_bytes": int(statistics.median(sample["anon_bytes"] for sample in samples)),
        "peak_rss_bytes": max(sample["rss_bytes"] for sample in samples),
        "hwm_bytes": max(sample["hwm_bytes"] for sample in samples),
        "cpu_seconds": cpu_seconds,
        "cpu_percent_of_quota": cpu_seconds / elapsed / cpus * 100,
    }


def measure_into(samples, seconds, read_sample, observe, sleep, monotonic, interval=SAMPLE_INTERVAL):
    """Include the terminal observation: the last sleep is still measured time."""
    started = monotonic()
    while True:
        observe()
        row = dict(read_sample())
        row["time"] = monotonic()
        samples.append(row)
        if exceeds_rss(row):
            raise Ceiling("RSS high-water mark reached " + str(row["hwm_bytes"]))
        remaining = seconds - (monotonic() - started)
        if remaining <= 0:
            return monotonic() - started
        sleep(min(interval, remaining))


def run_timed(result, name, seconds, read_sample, observe, cpu, ticks, monotonic, sleep):
    rows = result["samples"].setdefault(name, [])
    cpu_begin = cpu()
    elapsed = measure_into(rows, seconds, read_sample, observe, sleep, monotonic)
    result["phases"][name] = summarize(rows, elapsed, cpu() - cpu_begin, ticks)
    return result["phases"][name]


def active_rows(stats):
    rows = {}
    for row in stats.get("outbounds") or []:
        value = row.get("active")
        if type(value) is not int or value < 0 or type(row.get("tag")) is not str:
            raise StressError("invalid active connection statistics")
        rows[row["tag"]] = value
    return rows


def daemon_active(stats):
    return sum(active_rows(stats).values())


def server_tcp(payload):
    value = payload.get("tcp_connections")
    if type(value) is not int or value < 0:
        raise StressError("invalid server TCP count")
    return value


def counts_idle(server_count, daemon_count):
    if type(server_count) is not int or type(daemon_count) is not int or server_count < 0 or daemon_count < 0:
        raise FatalStress("invalid session counts")
    return server_count == 0 and daemon_count == 0


def require_idle_counts(server_count, daemon_count):
    if not counts_idle(server_count, daemon_count):
        raise StressError("TCP sessions remain")
    return True


def require_heavy_tunnel(stats):
    rows = active_rows(stats)
    if rows.get(HEAVY, -1) < STREAMS:
        raise StressError("AWG tunnel is not carrying 32 sessions")
    for tag, value in rows.items():
        if tag != HEAVY and value != 0:
            raise StressError("idle tunnel has active sessions")
    return True


def require_live(process, pid):
    if process is None or process.pid != pid:
        raise FatalStress("measured daemon pid changed")
    if process.poll() is not None:
        raise FatalStress("measured daemon exited")
    return True


def require_reaped(process):
    if process is None or process.poll() is None:
        raise StressError("stress client is still alive")
    return True


def parse_environ(blob):
    if type(blob) is not bytes:
        raise StressError("invalid process environ")
    values = {}
    for item in blob.split(b"\0"):
        if not item:
            continue
        if b"=" not in item:
            raise StressError("invalid process environ entry")
        key, value = item.split(b"=", 1)
        try:
            values[key.decode()] = value.decode()
        except UnicodeError as exc:
            raise StressError("invalid process environ entry") from exc
    return values


def require_daemon_environ(values):
    if values.get("GOMEMLIMIT") != "320MiB":
        raise StressError("measured daemon GOMEMLIMIT is not 320MiB")
    if values.get("GOGC") != "100" or values.get("GOMAXPROCS") != "2":
        raise StressError("measured daemon GOGC/GOMAXPROCS is not 100/2")
    return True


def require_server_environ(values):
    if values.get("GOMEMLIMIT") != "off":
        raise StressError("server GOMEMLIMIT must stay off")
    return True


def limit_view(values):
    return {key: values.get(key) for key in ("GOMEMLIMIT", "GOGC", "GOMAXPROCS")}


def capture_identity(daemon, server, binary, server_binary):
    """Verify exec completed for the actual configured binaries, not their names."""
    environments = {}
    for label, process, expected in (("keenproxy", daemon, binary), ("sbserver", server, server_binary)):
        require_live(process, process.pid)
        root = Path("/proc") / str(process.pid)
        actual = os.readlink(str(root / "exe"))
        if Path(actual).resolve() != Path(expected).resolve():
            raise StressError(label + " executable mismatch: " + actual)
        values = parse_environ((root / "environ").read_bytes())
        if label == "keenproxy":
            require_daemon_environ(values)
        else:
            require_server_environ(values)
        environments[label] = limit_view(values)
    return {"pid": daemon.pid, "environ": environments}


def only_process(fixture, label):
    matches = [process for name, process in fixture.processes if name == label]
    if len(matches) != 1:
        raise StressError("expected one " + label + " process")
    return matches[0]


def stop_owned(process, stop_path, wait_seconds=STOP_TIMEOUT, kill_seconds=KILL_TIMEOUT):
    """Bounded stop. A client that ignores the stop file is a failed run."""
    error = None
    try:
        stop_path.touch()
        process.wait(timeout=wait_seconds)
    except BaseException as exc:
        error = exc
        # A broken IPC path or wait must not leave traffic running. Kill and
        # reap before returning the failure, even when graceful stop is broken.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=kill_seconds)
    require_reaped(process)
    if error is not None:
        if isinstance(error, subprocess.TimeoutExpired):
            raise StressError("stress client stop timed out") from error
        raise error
    if process.returncode != 0:
        raise StressError("stress client failed: " + str(process.returncode))
    return process.returncode


def release_client(fixture, run_state):
    client = run_state.get("client")
    if client is None:
        return None
    process, _state_path, stop_path = client
    try:
        stop_owned(process, stop_path)
    finally:
        # poll() reaps on POSIX. Retain both owners if the stop attempt failed
        # with the process still alive, so recovery and Fixture cleanup retry.
        if process.poll() is not None:
            fixture.processes = [(label, item) for label, item in fixture.processes if item is not process]
            run_state["stopped"] = process
            run_state["client"] = None
    return process


def prefix_daemon(label, args):
    """Only keenproxy gets the soft limit. env exec keeps the ip-netns PID."""
    if label != "keenproxy":
        return tuple(args)
    return ("/usr/bin/env", "GOMEMLIMIT=320MiB", *tuple(args))


def rewrite_profile(profile):
    if profile.count("MTU = 1400\n") != 1 or profile.count("S2 = 8\n") != 1 or "S4 =" in profile:
        raise StressError("unexpected synthetic AWG profile")
    return profile.replace("MTU = 1400\n", "MTU = 1280\n", 1).replace("S2 = 8\n", "S2 = 8\nS4 = 12\n", 1)


def apply_transport(config, server):
    """Keep client and server MTU/S4 identical. S4 belongs only on the AWG pair."""
    connections, endpoints = config["connections"], server["endpoints"]
    if len(connections) != 2 or len(endpoints) != 2:
        raise StressError("stress fixture requires exactly two tunnels")
    awg, wg = connections
    awg_endpoint, wg_endpoint = endpoints
    if awg["type"] != "amneziawg" or wg["type"] != "wireguard" or "s4" in wg_endpoint:
        raise StressError("stress fixture requires AWG then idle WG")
    if awg_endpoint.get("s1") != 8 or awg_endpoint.get("s2") != 8:
        raise StressError("server AWG obfuscation drifted from the client")
    awg["amneziawg"] = rewrite_profile(awg["amneziawg"])
    awg_endpoint.update(mtu=MTU, s4=S4)
    wg["wireguard"]["mtu"] = MTU
    wg_endpoint["mtu"] = MTU
    return config, server


class StressFixture(scenario.Fixture):
    """Same namespaces and cleanup. Transport and the daemon limit are the only overrides."""

    def launch(self, namespace, label, *args):
        return super().launch(namespace, label, *prefix_daemon(label, args))

    def configuration(self):
        config, server = super().configuration()
        return apply_transport(config, server)


def bind_states(sockets):
    lookup, ordered = {}, []
    for index, sock in enumerate(sockets):
        state = {"index": index, "pending": b"", "verified": 0, "last": 0.0, "live": True}
        lookup[sock] = state
        ordered.append(state)
    return lookup, ordered


def close_all(sockets, errors):
    for sock in sockets:
        try:
            sock.close()
        except OSError as exc:
            errors.append("socket close failed: " + str(exc))


def open_streams(target, port, count, timeout, connect=socket.create_connection):
    sockets = []
    try:
        for _index in range(count):
            sock = connect((target, port), timeout)
            sockets.append(sock)
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sockets
    except Exception:
        close_all(sockets, [])
        raise


def finish_client(sockets, ordered, errors, seq, publish, monotonic, stop, stop_path, deadline):
    close_all(sockets, errors)
    for state in ordered:
        state["live"] = False
    if monotonic() >= deadline and not (stop.is_set() or stop_path.exists()):
        errors.append("client safety deadline")
    try:
        publish(publication(ordered, errors, monotonic(), seq + 1))
    except Exception as exc:
        errors.append(str(exc))


def run_client(sockets, lookup, ordered, stop, stop_path, publish, monotonic, select_fn, deadline, interval=0.1):
    errors, seq, next_publish = [], 0, 0.0
    try:
        while not stop.is_set() and not stop_path.exists() and monotonic() < deadline:
            now = monotonic()
            if now >= next_publish:
                seq += 1
                publish(publication(ordered, errors, now, seq))
                next_publish = now + interval
            pump_all(sockets, lookup, now, select_fn)
    except Exception as exc:
        errors.append(str(exc))
    finally:
        finish_client(sockets, ordered, errors, seq, publish, monotonic, stop, stop_path, deadline)
    return 1 if errors else 0


def install_stop(stop):
    def handler(_signum, _frame):
        stop.set()
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def client_main(target, state_path, stop_path):
    stop = threading.Event()
    install_stop(stop)
    try:
        sockets = open_streams(target, scenario.PORT, STREAMS, 8)
    except Exception as exc:
        scenario.save_json(state_path, publication([], [str(exc)], time.monotonic(), 1))
        return 1
    lookup, ordered = bind_states(sockets)
    return run_client(
        sockets, lookup, ordered, stop, Path(stop_path),
        lambda state: scenario.save_json(state_path, state),
        time.monotonic, select.select, time.monotonic() + CLIENT_DEADLINE)


def service_ready(client_process, daemon, pid, state, now, stats):
    require_live(daemon, pid)
    if client_process.poll() is not None:
        raise FatalStress("stress client exited before ready")
    if state is None:
        return False
    if state.get("errors"):
        raise FatalStress("transfer failed: " + repr(state["errors"]))
    if not ready_snapshot(state, now):
        return False
    require_heavy_tunnel(stats)
    return True


def read_state(path):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FatalStress("unreadable traffic publication") from exc
    if type(value) is not dict:
        raise FatalStress("unreadable traffic publication")
    return value


def session_counts(fixture):
    return server_tcp(read_state(fixture.directory / "server-active.json")), daemon_active(fixture.stats())


def zero_ready(process, pid, server_count, daemon_count):
    require_live(process, pid)
    return counts_idle(server_count, daemon_count)


def idle_observation(process, pid, server_count, daemon_count):
    require_live(process, pid)
    require_idle_counts(server_count, daemon_count)
    return True


def drain_observation(process, pid, client, server_count, daemon_count):
    """Zero is required on every drain sample, and the child must stay reaped."""
    require_live(process, pid)
    require_reaped(client)
    require_idle_counts(server_count, daemon_count)
    return True


def memory_reader(process, pid):
    def read_sample():
        require_live(process, pid)
        return read_memory(Path("/proc", str(pid), "status").read_text())
    return read_sample


def cpu_reader(pid):
    def read():
        return parse_cpu_ticks(Path("/proc", str(pid), "stat").read_text())
    return read


def wait_ready(fixture, client, monotonic=time.monotonic):
    process, state_path, _stop = client

    def ready():
        state = read_state(state_path) if state_path.exists() else None
        stats = fixture.stats() if state is not None else {}
        return service_ready(process, fixture.daemon, fixture.daemon.pid, state, monotonic(), stats)
    scenario.wait_for(ready, READY_TIMEOUT, "32 progressing AWG streams")


def wait_until_zero(fixture, pid):
    def drained():
        return zero_ready(fixture.daemon, pid, *session_counts(fixture))
    scenario.wait_for(drained, DRAIN_WAIT, "zero TCP sessions")


def launch_client(fixture):
    state_path = fixture.directory / "stress.json"
    stop_path = fixture.directory / "stress.stop"
    process = fixture.launch(
        fixture.client, "stress", sys.executable, str(Path(__file__)),
        "_stress", scenario.TARGETS[0], str(state_path), str(stop_path))
    return process, state_path, stop_path


def execute(fixture, result, run_state, monotonic=time.monotonic, sleep=time.sleep):
    fixture.setup()
    server = only_process(fixture, "sbserver")
    identity = capture_identity(fixture.daemon, server, fixture.args.binary, fixture.args.server)
    result["pid"] = identity["pid"]
    result["environ"] = identity["environ"]
    pid = identity["pid"]
    cpu, memory, ticks = cpu_reader(pid), memory_reader(fixture.daemon, pid), os.sysconf("SC_CLK_TCK")
    def idle():
        idle_observation(fixture.daemon, pid, *session_counts(fixture))

    run_timed(result, "idle", IDLE_SECONDS, memory, idle, cpu, ticks, monotonic, sleep)
    run_state["client"] = launch_client(fixture)
    wait_ready(fixture, run_state["client"], monotonic)
    before = read_state(run_state["client"][1])
    previous = None

    def loaded():
        nonlocal previous
        require_live(fixture.daemon, pid)
        require_live(run_state["client"][0], run_state["client"][0].pid)
        previous = load_observation(read_state(run_state["client"][1]), monotonic(), previous)

    run_timed(result, "loaded", LOAD_SECONDS, memory, loaded, cpu, ticks, monotonic, sleep)
    after = read_state(run_state["client"][1])
    require_load_rate(result, before, after)
    release_client(fixture, run_state)
    wait_until_zero(fixture, pid)

    def drained():
        drain_observation(fixture.daemon, pid, run_state["stopped"], *session_counts(fixture))

    run_timed(result, "drained", DRAIN_SECONDS, memory, drained, cpu, ticks, monotonic, sleep)


def new_result():
    return {
        "schema_version": 1,
        "variant": "candidate",
        "scenario": "amneziawg",
        "run": 1,
        "success": False,
        "settings": dict(SETTINGS),
        "limits": dict(LIMITS),
        "phases": {},
        "samples": {},
        "traffic": {},
    }


def attempt(action, result, key):
    """Secondary failures never bypass resource cleanup or replace the first error."""
    try:
        action()
    except BaseException as exc:
        result[key] = str(exc)
        result["success"] = False
        return exc
    return None


def guarded(directory, output, cleanup, fixture, run_state, body):
    result, error = new_result(), None
    try:
        body(result)
        result["success"] = True
    except BaseException as exc:
        error = exc
        result["error"] = str(exc)
        failure_trace = traceback.format_exc()
        # Stop first, before logging or expensive diagnostics. A failed stop
        # retains ownership until poll confirms reaping; cleanup retries it.
        attempt(lambda: release_client(fixture, run_state), result, "stop_error")
        if run_state.get("client") is None:
            attempt(fixture.failure_snapshot, result, "diagnostic_error")
        attempt(lambda: (directory / "failure.log").write_text(failure_trace) if directory.exists() else None, result, "failure_log_error")
    finally:
        # Keep persistence independent of teardown. In particular, full disks
        # must not strand clients, daemons, or namespaces.
        attempt(lambda: scenario.save_json(directory / "stats.json", getattr(fixture, "stats_samples", [])) if directory.exists() else None, result, "stats_error")
        cleanup_error = attempt(cleanup.close, result, "cleanup_error")
        if cleanup_error and directory.exists():
            result["retained_artifacts"] = str(directory)
        persistence_error = attempt(lambda: scenario.save_json(output, result), result, "result_error")
    if error is not None:
        raise StressError(str(error)) from error
    if not result["success"]:
        message = next((result[key] for key in ("cleanup_error", "stats_error", "result_error") if key in result), "stress failed")
        raise StressError(message) from (cleanup_error or persistence_error)
    return result


def install_preserve(cleanup, directory, output, flag):
    def preserve():
        if directory.exists():
            shutil.copytree(directory, output.with_suffix(".artifacts"))
            flag["preserved"] = True
    cleanup.add(lambda: shutil.rmtree(directory) if flag.get("preserved") else None)
    cleanup.add(preserve)


def run(args):
    os.umask(0o077)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cleanup = scenario.Cleanup()
    directory = Path("/tmp") / ("keenproxy-stress-" + uuid.uuid4().hex)
    install_preserve(cleanup, directory, output, {})
    fixture = StressFixture(args, directory, cleanup)
    run_state = {}

    def body(result):
        directory.mkdir()
        execute(fixture, result, run_state)
    return guarded(directory, output, cleanup, fixture, run_state, body)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    args.scenario = "amneziawg"
    args.variant = "candidate"
    args.run = 1
    return args


def interrupt(signum, _frame):
    raise StressError("stress interrupted by signal " + str(signum))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["_stress"]:
        if len(argv) != 4:
            raise StressError("invalid stress helper arguments")
        return client_main(argv[1], Path(argv[2]), Path(argv[3]))
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    run(parse_args(argv))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("memory stress failed: " + str(exc), file=sys.stderr)
        sys.exit(1)

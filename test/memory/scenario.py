#!/usr/bin/env python3
"""Measure a real Linux daemon in uniquely owned, disposable namespaces.

TCP and UDP both run during measured load. Draining proves TCP closure at
clients and server while the same two UDP sockets keep exchanging payloads.
No production diagnostics, runtime GC requests, or external endpoints are used.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import socketserver
import statistics
import subprocess
import sys
import threading
import time
import traceback
import uuid

TAGS = ("wg1", "wg2")
TARGETS = ("203.0.113.81", "203.0.113.82")
PORT = 18080


class ScenarioError(RuntimeError):
    pass


def parse_status(text):
    values = {}
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] in ("VmRSS:", "RssAnon:"):
            if len(parts) != 3 or parts[2] != "kB" or not parts[1].isdigit():
                raise ScenarioError("invalid procfs memory field: " + line)
            values[parts[0]] = int(parts[1]) * 1024
    rss, anon = values.get("VmRSS:", 0), values.get("RssAnon:", 0)
    if not 0 < anon <= rss:
        raise ScenarioError("missing or inconsistent procfs RSS/anonymous RSS")
    return {"rss_bytes": rss, "anon_bytes": anon}


def phase_metrics(samples):
    if not samples:
        raise ScenarioError("phase has no memory samples")
    return {"rss_bytes": int(statistics.median(s["rss_bytes"] for s in samples)),
            "anon_bytes": int(statistics.median(s["anon_bytes"] for s in samples)),
            "peak_rss_bytes": max(s["rss_bytes"] for s in samples)}


def active_connections(stats, loaded=False):
    rows = stats.get("outbounds") or []
    values = {}
    for row in rows:
        value = row.get("active")
        if type(value) is not int or value < 0:
            raise ScenarioError("invalid active connection statistics")
        values[row["tag"]] = value
    if loaded and any(values.get(tag, 0) < 16 for tag in TAGS):
        raise ScenarioError("both tunnels must each carry 16 concurrent sessions")
    return sum(values.values())


def validate_traffic(state, minimum=0, protocols=("tcp", "udp")):
    if state.get("errors"):
        raise ScenarioError("traffic failure: " + repr(state["errors"]))
    if state.get("connected", 0) < minimum:
        raise ScenarioError("traffic lost concurrent sessions")
    for protocol in protocols:
        values = state.get(protocol + "_bytes", {})
        if any(type(values.get(tag)) is not int or values[tag] <= 0 for tag in TAGS):
            raise ScenarioError("missing verified " + protocol + " payload on both tunnels")


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ScenarioError("echo stream closed before complete payload")
        chunks.extend(part)
    return bytes(chunks)


def save_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


class Cleanup:
    def __init__(self):
        self.callbacks = []

    def add(self, callback):
        self.callbacks.append(callback)

    def close(self):
        errors = []
        while self.callbacks:
            try:
                self.callbacks.pop()()
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise ScenarioError("cleanup failed: " + "; ".join(errors))


def command(args, **kwargs):
    try:
        return subprocess.run([str(x) for x in args], check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=kwargs.pop("timeout", 20), **kwargs).stdout
    except subprocess.CalledProcessError as exc:
        raise ScenarioError(f"command {args!r} failed: {exc.stderr}") from exc


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.poll() is None:
        raise ScenarioError("owned process remains alive")


def wait_for(predicate, seconds, description):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, subprocess.SubprocessError, ScenarioError) as exc:
            last = exc
        time.sleep(0.2)
    raise ScenarioError("timed out waiting for " + description + ": " + str(last))


class UDPProgress:
    """Require recent payload echoes and advancing bytes, not residual mappings."""
    def __init__(self):
        self.bytes = {}
        self.changed = {}

    def observe(self, state, now=None):
        now = time.monotonic() if now is None else now
        validate_traffic(state, protocols=("udp",))
        for tag in TAGS:
            last = state.get("udp_last_success", {}).get(tag, 0)
            if type(last) not in (int, float) or last <= 0 or not 0 <= now - last <= 2:
                raise ScenarioError("stale UDP echo on " + tag)
            count = state["udp_bytes"][tag]
            if count > self.bytes.get(tag, 0):
                self.bytes[tag], self.changed[tag] = count, now
            if now - self.changed.get(tag, now) > 2:
                raise ScenarioError("UDP payload bytes stopped advancing on " + tag)


class ProcSampler:
    """One writer samples a fixed live process until explicitly joined."""
    def __init__(self, process, samples, cleanup):
        self.process, self.samples = process, samples
        self.stop = threading.Event()
        self.error = None
        self.thread = None
        cleanup.add(self.close)

    def start(self):
        self.thread = threading.Thread(target=self.collect, name="memory-proc-sampler")
        self.thread.start()

    def collect(self):
        try:
            while not self.stop.is_set():
                if self.process.poll() is not None:
                    raise ScenarioError("measured daemon exited during reconfiguration")
                row = parse_status(Path(f"/proc/{self.process.pid}/status").read_text())
                row.update({"time": time.monotonic(), "stage": "reconfiguration"})
                self.samples.append(row)
                self.stop.wait(0.2)
        except Exception as exc:
            self.error = exc
            self.stop.set()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise ScenarioError("procfs sampler failed to stop")
        if self.error is not None:
            error, self.error = self.error, None
            raise ScenarioError("procfs sampler failed: " + str(error)) from error


class Fixture:
    def __init__(self, args, directory, cleanup):
        self.args, self.directory, self.cleanup = args, directory, cleanup
        token = uuid.uuid4().hex[:10]
        self.router, self.client, self.wan = ["mem-" + token + suffix for suffix in ("-r", "-c", "-w")]
        self.processes = []
        self.daemon = None
        self.stats_samples = []
        self.traffic_index = 0
        self.token = "synthetic-memory-fixture-token"
        self.script = Path(__file__).resolve()
        self.current_traffic = None
        self.udp_progress = UDPProgress()

    def ip(self, namespace, *args):
        return command(["ip", "-n", namespace, *args])

    def execute(self, namespace, *args, **kwargs):
        return command(["ip", "netns", "exec", namespace, *args], **kwargs)

    def remove_namespace(self, name):
        names = command(["ip", "netns", "list"])
        if name not in [line.split()[0] for line in names.splitlines()]:
            return
        pids = command(["ip", "netns", "pids", name]).split()
        if pids:
            raise ScenarioError("owned namespace still contains processes: " + name + " " + repr(pids))
        command(["ip", "netns", "delete", name])
        if name in [line.split()[0] for line in command(["ip", "netns", "list"]).splitlines()]:
            raise ScenarioError("owned namespace remains: " + name)

    def launch(self, namespace, label, *args):
        log = open(self.directory / (label + ".log"), "w")
        self.cleanup.add(log.close)
        owned = []
        self.cleanup.add(lambda: [stop_process(process) for process in owned])
        process = subprocess.Popen(["ip", "netns", "exec", namespace, *map(str, args)], stdout=log, stderr=subprocess.STDOUT)
        owned.append(process)
        self.processes.append((label, process))
        return process

    def healthy(self):
        for label, process in self.processes:
            if process.poll() is not None:
                raise ScenarioError(label + " exited with status " + str(process.returncode))

    def install_routes(self):
        # Network monitoring requires a default interface to keep WG devices
        # active. Host routes still prohibit bypassing either hidden target.
        for target in TARGETS:
            self.ip(self.router, "route", "add", "unreachable", target + "/32")
        self.ip(self.router, "route", "add", "default", "via", "198.51.100.2", "dev", "wan0")
        self.ip(self.wan, "route", "add", "default", "via", "198.51.100.1", "dev", "eth0")
        self.ip(self.client, "route", "add", "default", "via", "192.168.77.1")

    def setup(self):
        for name in (self.router, self.client, self.wan):
            self.cleanup.add(lambda name=name: self.remove_namespace(name))
            command(["ip", "netns", "add", name])
            self.ip(name, "link", "set", "lo", "up")
        # All links and firewall rules live inside the owned router namespace.
        for name, peer, address, remote in ((self.client, "lan0", "192.168.77.1/24", "192.168.77.10/24"),
                                           (self.wan, "wan0", "198.51.100.1/24", "198.51.100.2/24")):
            self.ip(self.router, "link", "add", peer, "type", "veth", "peer", "name", "eth0", "netns", name)
            self.ip(self.router, "addr", "add", address, "dev", peer)
            self.ip(self.router, "link", "set", peer, "up")
            self.ip(name, "addr", "add", remote, "dev", "eth0")
            self.ip(name, "link", "set", "eth0", "up")
        self.install_routes()
        self.execute(self.router, "sysctl", "-w", "net.ipv4.ip_forward=1")
        for target in TARGETS:
            self.ip(self.wan, "addr", "add", target + "/32", "dev", "lo")
        if not Path("/dev/net/tun").exists():
            Path("/dev/net").mkdir(parents=True, exist_ok=True)
            os.mknod("/dev/net/tun", 0o20666, os.makedev(10, 200))
        self.launch(self.wan, "echo", sys.executable, self.script, "_echo", self.directory / "server-active.json")
        # Explicit unreachable host routes override the synthetic default.
        for target in TARGETS:
            result = subprocess.run(["ip", "-n", self.router, "route", "get", target], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                raise ScenarioError("negative control: router unexpectedly routes to " + target)
            result = subprocess.run(["ip", "netns", "exec", self.client, sys.executable, self.script, "_probe", target], capture_output=True, text=True, timeout=5)
            (self.directory / ("negative-" + target + ".log")).write_text(result.stdout + result.stderr)
            if result.returncode == 0:
                raise ScenarioError("negative control unexpectedly reached hidden target")
        config, server = self.configuration()
        config_path, server_path = self.directory / "config.yaml", self.directory / "server.json"
        # JSON is a YAML subset, accepted by the normal daemon loader.
        save_json(config_path, config)
        save_json(server_path, server)
        (self.directory / "token").write_text(self.token + "\n")
        self.launch(self.wan, "sbserver", self.args.server, server_path)
        self.daemon = self.launch(self.router, "keenproxy", self.args.binary,
                                  "-config", config_path, "-rule-sets", self.directory / "rule-sets", "-watch", "1s",
                                  "-iptables", "/usr/sbin/iptables", "-iptables-restore", "/usr/sbin/iptables-restore")
        wait_for(lambda: self.ready(), 30, "daemon API and interception readiness")

    def configuration(self):
        connections, endpoints = [], []
        for index, tag in enumerate(TAGS, 1):
            private = base64.b64encode(bytes([index]) * 32).decode()
            server_private = base64.b64encode(bytes([index + 10]) * 32).decode()
            public = command(["wg", "pubkey"], input=private + "\n").strip()
            server_public = command(["wg", "pubkey"], input=server_private + "\n").strip()
            awg = self.args.scenario == "amneziawg" and index == 1
            endpoint = {"type": "wireguard", "tag": tag, "system": True, "name": "memwg" + str(index),
                        "address": [f"10.71.{index}.1/30"], "private_key": server_private,
                        "listen_port": 51820 + index, "mtu": 1400,
                        "peers": [{"public_key": public, "allowed_ips": [f"10.71.{index}.2/32"]}]}
            connection = {"id": tag, "type": "wireguard", "wireguard": {
                "private_key": private, "address": [f"10.71.{index}.2/30"], "mtu": 1400,
                "peer": {"public_key": server_public, "endpoint": f"198.51.100.2:{51820 + index}", "allowed_ips": ["0.0.0.0/0"]}}}
            if awg:
                # Non-default header values force the actual AWG device path.
                endpoint.update({"jc": 1, "jmin": 16, "jmax": 32, "s1": 8, "s2": 8,
                                 "h1": 101, "h2": 102, "h3": 103, "h4": 104})
                profile = (f"[Interface]\nPrivateKey = {private}\nAddress = 10.71.{index}.2/30\nMTU = 1400\n"
                           "Jc = 1\nJmin = 16\nJmax = 32\nS1 = 8\nS2 = 8\nH1 = 101\nH2 = 102\nH3 = 103\nH4 = 104\n"
                           f"[Peer]\nPublicKey = {server_public}\nEndpoint = 198.51.100.2:{51820 + index}\nAllowedIPs = 0.0.0.0/0\n")
                connection = {"id": tag, "type": "amneziawg", "amneziawg": profile}
            connections.append(connection)
            endpoints.append(endpoint)
        config = {"schema_version": 1, "api": {"listen": "127.0.0.1:8086", "token_file": str(self.directory / "token")},
                  "lan": {"interface": "lan0", "wan": "wan0"},
                  "dns": {"listen": "0.0.0.0:5354", "upstreams": ["udp://198.51.100.2:53"], "fallback": "198.51.100.2:53"},
                  # Explicit existing built-in disables the fresh-config defaults;
                  # model defaults append all other built-ins disabled as well.
                  "geoip": {"databases": [{"id": "dbip", "enabled": False}]},
                  "intercept": {"mode": "tproxy"}, "connections": connections,
                  "groups": [{"name": tag, "target": tag, "entries": [target]} for tag, target in zip(TAGS, TARGETS)],
                  "networks": [{"name": "Synthetic LAN", "cidr": "192.168.77.0/24", "mode": "split"}]}
        return config, {"log": {"level": "debug"}, "endpoints": endpoints, "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}

    def api(self, path, value=None):
        args = ["curl", "--fail-with-body", "--silent", "--show-error", "--max-time", "15", "-H", "Authorization: Bearer " + self.token]
        if value is not None:
            args += ["-X", "PUT", "-H", "Content-Type: application/json", "--data-binary", json.dumps(value)]
        raw = self.execute(self.router, *args, "http://127.0.0.1:8086/api/" + path)
        return json.loads(raw)

    def ready(self):
        self.healthy()
        self.api("config")
        self.execute(self.router, "iptables", "-t", "nat", "-C", "PREROUTING", "-j", "KEENPROXY_TCP")
        self.execute(self.router, "iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "KEENPROXY_UDP")
        return True

    def stats(self):
        self.healthy()
        value = self.api("stats")
        self.stats_samples.append({"time": time.monotonic(), "stats": value})
        return value

    def phase(self, name, duration, samples, traffic=None):
        rows = samples.setdefault(name, [])
        end = time.monotonic() + duration
        while time.monotonic() < end:
            self.healthy()
            stats = self.stats()
            active = active_connections(stats, loaded=traffic is not None)
            if traffic is None:
                if name == "idle" and active != 0:
                    raise ScenarioError("idle phase has active sessions")
                if name != "idle":
                    self.drained(stats)
                    state = json.loads(self.current_traffic.read_text())
            else:
                state = json.loads(traffic.read_text())
                validate_traffic(state, 32)
                self.udp_progress.observe(state)
            row = parse_status(Path(f"/proc/{self.daemon.pid}/status").read_text())
            row.update({"time": time.monotonic(), "active_connections": active})
            if traffic is not None or name != "idle":
                row["traffic"] = state
            row["server_tcp_connections"] = json.loads((self.directory / "server-active.json").read_text())["tcp_connections"]
            rows.append(row)
            time.sleep(0.2)
        return phase_metrics(rows)

    def start_traffic(self):
        self.traffic_index += 1
        prefix = self.directory / ("traffic-" + str(self.traffic_index))
        state_path, stop_path = prefix.with_suffix(".json"), prefix.with_suffix(".stop")
        process = self.launch(self.client, prefix.name, sys.executable, self.script, "_traffic", state_path, stop_path)
        self.current_traffic = state_path
        self.udp_progress = UDPProgress()
        def loaded():
            self.healthy()
            if not state_path.exists():
                return False
            validate_traffic(json.loads(state_path.read_text()), 32)
            active_connections(self.stats(), loaded=True)
            return True
        wait_for(loaded, 30, "32 payload-verified TCP sessions on both tunnels")
        return process, state_path, stop_path

    def drain_tcp(self, traffic):
        process, state_path, stop_path = traffic
        stop_path.with_suffix(".tcp-stop").touch()
        def drained():
            self.healthy()
            state = json.loads(state_path.read_text())
            validate_traffic(state)
            if state["connected"] != 0:
                return False
            return self.drained(self.stats())
        wait_for(drained, 20, "TCP closure with two verified live UDP sessions")

    def finish_traffic(self, traffic):
        process, state_path, stop_path = traffic
        stop_path.touch()
        process.wait(timeout=10)
        if process.returncode:
            raise ScenarioError("traffic process failed")
        self.processes = [(label, p) for label, p in self.processes if p is not process]
        state = json.loads(state_path.read_text())
        validate_traffic(state)
        if state["connected"] != 0:
            raise ScenarioError("client TCP sessions did not close")
        self.current_traffic = None
        return state

    def drained(self, stats):
        server = json.loads((self.directory / "server-active.json").read_text())
        if server["tcp_connections"] != 0:
            raise ScenarioError("server still has active TCP sessions")
        state = json.loads(self.current_traffic.read_text())
        if state["connected"] != 0:
            raise ScenarioError("client still has active TCP sessions")
        self.udp_progress.observe(state)
        rows = {row["tag"]: row["active"] for row in stats.get("outbounds") or []}
        if active_connections(stats) != 2 or any(rows.get(tag) != 1 for tag in TAGS):
            raise ScenarioError("daemon must have exactly the two verified live UDP sessions")
        return True

    def failure_snapshot(self):
        """Retain only owned synthetic topology, before cleanup removes it."""
        snapshots = {}
        commands = (["ip", "-details", "address", "show"],
                    ["ip", "-s", "link", "show"],
                    ["ip", "route", "show", "table", "all"],
                    ["ip", "rule", "show"],
                    ["ss", "-tunap"],
                    ["cat", "/proc/net/udp"],
                    ["cat", "/proc/net/udp6"])
        for namespace in (self.router, self.client, self.wan):
            rows = []
            for args in commands:
                try:
                    text = self.execute(namespace, *args, timeout=5)
                except Exception as exc:
                    text = "snapshot failed: " + str(exc)
                rows.append({"command": args, "output": text})
            snapshots[namespace] = rows
        try:
            snapshots["api_stats"] = self.api("stats")
        except Exception as exc:
            snapshots["api_stats_error"] = str(exc)
        save_json(self.directory / "failure-topology.json", snapshots)


def echo_server(active_path):
    lock = threading.Lock()
    active = 0
    def update(delta):
        nonlocal active
        with lock:
            active += delta
            save_json(active_path, {"tcp_connections": active})
    update(0)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            update(1)
            try:
                self.request.settimeout(5)
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        return
                    self.request.sendall(data)
            except OSError:
                return
            finally:
                update(-1)
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(data, self.client_address)
    class TCPServer(socketserver.ThreadingTCPServer):
        request_queue_size = 128
        allow_reuse_address = True
        daemon_threads = True
    servers = []
    threads = []
    try:
        for target in TARGETS:
            for kind, handler in ((TCPServer, TCP), (socketserver.ThreadingUDPServer, UDP)):
                server = kind((target, PORT), handler)
                servers.append(server)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                threads.append(thread)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)


def traffic_worker(state_path, stop_path):
    state = {"tcp_bytes": {tag: 0 for tag in TAGS}, "udp_bytes": {tag: 0 for tag in TAGS},
             "udp_last_success": {tag: 0 for tag in TAGS}, "connected": 0, "errors": []}
    lock, stop = threading.Lock(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    def worker(index):
        tag, target = TAGS[index % 2], TARGETS[index % 2]
        payload = (f"memory-{index:02d}:".encode() + bytes(range(256))) * 16
        connected = False
        try:
            with socket.create_connection((target, PORT), timeout=8) as sock:
                sock.settimeout(4)
                while not stop.is_set() and not Path(stop_path).exists() and not Path(stop_path).with_suffix(".tcp-stop").exists():
                    sock.sendall(payload)
                    if receive_exact(sock, len(payload)) != payload:
                        raise ScenarioError("TCP echo payload mismatch on " + tag)
                    if not connected:
                        with lock:
                            state["connected"] += 1
                        connected = True
                    with lock:
                        state["tcp_bytes"][tag] += len(payload)
                    stop.wait(0.05)
        except Exception as exc:
            with lock:
                state["errors"].append(str(exc))
            stop.set()
        finally:
            if connected:
                with lock:
                    state["connected"] -= 1
    def udp(index):
        tag, target = TAGS[index], TARGETS[index]
        payload = ("memory-udp-" + tag).encode() * 64
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(4)
                sock.connect((target, PORT))
                while not stop.is_set() and not Path(stop_path).exists():
                    sock.send(payload)
                    if sock.recv(65536) != payload:
                        raise ScenarioError("UDP echo payload mismatch on " + tag)
                    with lock:
                        state["udp_bytes"][tag] += len(payload)
                        state["udp_last_success"][tag] = time.monotonic()
                    stop.wait(0.1)
        except Exception as exc:
            with lock:
                state["errors"].append(str(exc))
            stop.set()
    threads = [threading.Thread(target=worker, args=(index,)) for index in range(32)]
    threads.extend(threading.Thread(target=udp, args=(index,)) for index in range(2))
    try:
        for thread in threads:
            thread.start()
        while not stop.is_set() and not Path(stop_path).exists():
            with lock:
                save_json(state_path, state)
            stop.wait(0.1)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in threads):
            state["errors"].append("traffic thread failed to stop")
        save_json(state_path, state)
    return 1 if state["errors"] else 0




def run(args):
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cleanup = Cleanup()
    # Keep live IPC on the container filesystem, not a host bind mount.
    # Atomic state publication must not depend on host file-sharing semantics.
    directory = Path("/tmp") / ("keenproxy-memory-" + uuid.uuid4().hex)
    preserved = False
    def preserve():
        nonlocal preserved
        if directory.exists():
            shutil.copytree(directory, output.with_suffix(".artifacts"))
            preserved = True
    cleanup.add(lambda: shutil.rmtree(directory) if preserved else None)
    cleanup.add(preserve)
    fixture = Fixture(args, directory, cleanup)
    result = {"schema_version": 1, "variant": args.variant, "scenario": args.scenario, "run": args.run,
              "phases": {}, "samples": {}}
    error = None
    try:
        directory.mkdir()
        fixture.setup()
        result["phases"]["idle"] = fixture.phase("idle", 5, result["samples"])
        traffic = fixture.start_traffic()
        result["phases"]["loaded"] = fixture.phase("loaded", 10, result["samples"], traffic[1])
        fixture.drain_tcp(traffic)
        result["phases"]["drained"] = fixture.phase("drained", 10, result["samples"])
        fixture.drained(fixture.stats())
        drained_udp_connections = 2
        state = fixture.finish_traffic(traffic)
        tcp_bytes = state["tcp_bytes"].copy()
        udp_bytes = state["udp_bytes"].copy()
        apply_count = 0
        sampler = ProcSampler(fixture.daemon, result["samples"].setdefault("reapplied", []), cleanup)
        sampler.start()
        for cycle in range(3):
            config = fixture.api("config")
            # MTU is engine configuration, not just a label: every PUT rebuilds
            # endpoints with a genuinely changed transport setting.
            for connection in config["connections"]:
                if connection["type"] == "wireguard":
                    connection["wireguard"]["mtu"] = 1380 - cycle * 10
                else:
                    connection["amneziawg"] = connection["amneziawg"].replace("MTU = " + str(1400 if cycle == 0 else 1380 - (cycle - 1) * 10), "MTU = " + str(1380 - cycle * 10))
            save_json(directory / f"apply-{cycle + 1}.json", config)
            fixture.api("config", config)
            apply_count += 1
            traffic = fixture.start_traffic()
            # New payloads on both tunnels prove every Apply remains usable.
            time.sleep(1)
            fixture.drain_tcp(traffic)
            if cycle < 2:
                state = fixture.finish_traffic(traffic)
                for tag in TAGS:
                    tcp_bytes[tag] += state["tcp_bytes"][tag]
                    udp_bytes[tag] += state["udp_bytes"][tag]
        # Join the background writer before the main thread appends steady
        # drained samples. The phase peak therefore includes every Apply.
        sampler.close()
        result["phases"]["reapplied"] = fixture.phase("reapplied", 10, result["samples"])
        fixture.drained(fixture.stats())
        state = fixture.finish_traffic(traffic)
        for tag in TAGS:
            tcp_bytes[tag] += state["tcp_bytes"][tag]
            udp_bytes[tag] += state["udp_bytes"][tag]
        result["evidence"] = {"tcp_bytes": tcp_bytes, "udp_bytes": udp_bytes,
                              "apply_count": apply_count, "loaded_connections": 32,
                              "drained_connections": 0,
                              "drained_udp_connections": drained_udp_connections,
                              "udp_during_load": True, "udp_drain_verified": True}
        validate_traffic(result["evidence"])
    except BaseException as exc:
        error = exc
        result["error"] = str(exc)
        (directory / "failure.log").write_text(traceback.format_exc())
        try:
            fixture.failure_snapshot()
        except Exception as snapshot_error:
            result["snapshot_error"] = str(snapshot_error)
    finally:
        try:
            save_json(directory / "stats.json", fixture.stats_samples)
        finally:
            try:
                cleanup.close()
            except Exception as exc:
                result["cleanup_error"] = str(exc)
                if directory.exists():
                    result["retained_artifacts"] = str(directory)
                error = error or exc
            save_json(output, result)
    if error:
        raise ScenarioError(str(error))


def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        mode = sys.argv[1]
        if mode == "_echo":
            echo_server(sys.argv[2])
        elif mode == "_traffic":
            return traffic_worker(sys.argv[2], sys.argv[3])
        elif mode == "_probe":
            with socket.create_connection((sys.argv[2], PORT), timeout=1):
                pass
        else:
            raise ScenarioError("unknown helper mode")
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scenario", choices=("wireguard", "amneziawg"), required=True)
    parser.add_argument("--variant", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--run", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    if args.scenario == "amneziawg" and args.variant != "candidate":
        parser.error("AmneziaWG evidence is current-only")
    def interrupted(signum, frame):
        raise ScenarioError("scenario interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    run(args)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("memory scenario failed: " + str(exc), file=sys.stderr)
        sys.exit(1)

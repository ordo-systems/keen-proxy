"""Unit coverage for the Linux fixture's fail-closed boundaries."""
import importlib.util
from pathlib import Path
import json
from types import SimpleNamespace
import tempfile
import unittest
import threading
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("memory_scenario", Path(__file__).with_name("scenario.py"))
scenario = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scenario)


class ScenarioTests(unittest.TestCase):
    def test_sampler_captures_reconfiguration_and_cleanup_joins_thread(self):
        sampled = threading.Event()
        cleanup, rows = scenario.Cleanup(), []
        self.addCleanup(cleanup.close)
        sampler = scenario.ProcSampler(SimpleNamespace(pid=123, poll=lambda: None), rows, cleanup)
        def status():
            sampled.set()
            return "VmRSS: 2048 kB\nRssAnon: 1024 kB\n"
        with patch.object(scenario.Path, "read_text", side_effect=status):
            sampler.start()
            self.assertTrue(sampled.wait(timeout=2))
            cleanup.close()
        self.assertFalse(sampler.thread.is_alive())
        self.assertTrue(rows)
        self.assertEqual(rows[0]["stage"], "reconfiguration")
        self.assertEqual(scenario.phase_metrics(rows)["peak_rss_bytes"], 2097152)

    def test_sampler_read_error_fails_and_cleanup_still_joins(self):
        attempted = threading.Event()
        cleanup = scenario.Cleanup()
        self.addCleanup(cleanup.close)
        sampler = scenario.ProcSampler(SimpleNamespace(pid=123, poll=lambda: None), [], cleanup)
        def unavailable():
            attempted.set()
            raise OSError("procfs disappeared")
        with patch.object(scenario.Path, "read_text", side_effect=unavailable):
            sampler.start()
            self.assertTrue(attempted.wait(timeout=2))
            with self.assertRaisesRegex(scenario.ScenarioError, "procfs disappeared"):
                cleanup.close()
        self.assertFalse(sampler.thread.is_alive())
        cleanup.close()

    def test_sampler_rejects_daemon_exit_without_sampling_a_reused_pid(self):
        sampler = scenario.ProcSampler(SimpleNamespace(pid=123, poll=lambda: 1), [], scenario.Cleanup())
        with patch.object(scenario.Path, "read_text") as read:
            sampler.collect()
            with self.assertRaisesRegex(scenario.ScenarioError, "daemon exited"):
                sampler.close()
        read.assert_not_called()

    def test_default_interfaces_preserve_explicit_unreachable_target_routes(self):
        fixture = scenario.Fixture(SimpleNamespace(), Path("/synthetic"), scenario.Cleanup())
        with patch.object(fixture, "ip") as ip:
            fixture.install_routes()
        calls = [call.args for call in ip.call_args_list]
        self.assertEqual(calls[:2], [
            (fixture.router, "route", "add", "unreachable", target + "/32")
            for target in scenario.TARGETS])
        self.assertIn((fixture.router, "route", "add", "default", "via", "198.51.100.2", "dev", "wan0"), calls[2:])
        self.assertIn((fixture.wan, "route", "add", "default", "via", "198.51.100.1", "dev", "eth0"), calls[2:])

    def test_configuration_keeps_two_distinct_peers_and_disables_geo_downloads(self):
        fixture = scenario.Fixture(SimpleNamespace(scenario="wireguard"), Path("/synthetic"), scenario.Cleanup())
        with patch.object(scenario, "command", side_effect=["client1", "server1", "client2", "server2"]):
            config, server = fixture.configuration()
        self.assertEqual(config["geoip"]["databases"], [{"id": "dbip", "enabled": False}])
        self.assertEqual([row["wireguard"]["peer"]["endpoint"] for row in config["connections"]],
                         ["198.51.100.2:51821", "198.51.100.2:51822"])
        self.assertEqual([row["listen_port"] for row in server["endpoints"]], [51821, 51822])
        self.assertEqual([row["peers"][0]["public_key"] for row in server["endpoints"]], ["client1", "client2"])

    def test_failure_snapshot_preserves_partial_evidence_when_a_command_fails(self):
        with tempfile.TemporaryDirectory(prefix="memory-fixture-unit-") as directory:
            fixture = scenario.Fixture(SimpleNamespace(), Path(directory), scenario.Cleanup())
            def execute(namespace, *args, **kwargs):
                if args[0] == "ss":
                    raise scenario.ScenarioError("socket inspection unavailable")
                return namespace + ": " + " ".join(args)
            with patch.object(fixture, "execute", side_effect=execute), patch.object(fixture, "api", return_value={"outbounds": []}):
                fixture.failure_snapshot()
            value = json.loads((Path(directory) / "failure-topology.json").read_text())
            self.assertEqual(value["api_stats"], {"outbounds": []})
            self.assertTrue(any("socket inspection unavailable" in row["output"] for row in value[fixture.wan]))

    def test_proc_metrics_use_current_rss_not_lifetime_high_water(self):
        metrics = scenario.parse_status("VmRSS:\t2048 kB\nRssAnon: 1024 kB\nVmHWM: 9999 kB\n")
        self.assertEqual(metrics, {"rss_bytes": 2097152, "anon_bytes": 1048576})
        self.assertEqual(scenario.parse_status("VmRSS: 1 kB\nRssAnon: 1 kB\n"),
                         {"rss_bytes": 1024, "anon_bytes": 1024})

    def test_proc_metrics_reject_incomplete_or_inconsistent_values(self):
        for text in ("", "VmRSS: 1 kB", "VmRSS: 1 kB\nRssAnon: 2 kB", "VmRSS: 0 kB\nRssAnon: 0 kB", "VmRSS: 2 MB\nRssAnon: 1 kB"):
            with self.subTest(text=text), self.assertRaises(scenario.ScenarioError):
                scenario.parse_status(text)

    def test_phase_uses_median_and_phase_local_peak(self):
        samples = [{"rss_bytes": n, "anon_bytes": n // 2} for n in (100, 300, 200)]
        self.assertEqual(scenario.phase_metrics(samples), {"rss_bytes": 200, "anon_bytes": 100, "peak_rss_bytes": 300})
        with self.assertRaises(scenario.ScenarioError):
            scenario.phase_metrics([])

    def test_traffic_requires_both_protocols_and_tunnels(self):
        evidence = {"tcp_bytes": {"wg1": 10, "wg2": 20}, "udp_bytes": {"wg1": 30, "wg2": 40}, "errors": [], "connected": 32}
        scenario.validate_traffic(evidence, 32)
        for field in ("tcp_bytes", "udp_bytes"):
            evidence[field]["wg2"] = 0
            with self.assertRaises(scenario.ScenarioError):
                scenario.validate_traffic(evidence, 32)
            evidence[field]["wg2"] = 10
        evidence["errors"] = ["payload mismatch"]
        with self.assertRaises(scenario.ScenarioError):
            scenario.validate_traffic(evidence, 32)

    def test_lifecycle_checks_each_tunnel_not_just_total(self):
        stats = {"outbounds": [{"tag": "wg1", "active": 16}, {"tag": "wg2", "active": 16}]}
        self.assertEqual(scenario.active_connections(stats, loaded=True), 32)
        stats["outbounds"][1]["active"] = 0
        with self.assertRaises(scenario.ScenarioError):
            scenario.active_connections(stats, loaded=True)
        stats["outbounds"][0]["active"] = -1
        with self.assertRaises(scenario.ScenarioError):
            scenario.active_connections(stats)

    def test_echo_verification_handles_tcp_segmentation_and_eof(self):
        class Stream:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
            def recv(self, size):
                return next(self.chunks, b"")
        self.assertEqual(scenario.receive_exact(Stream([b"ab", b"cd"]), 4), b"abcd")
        with self.assertRaises(scenario.ScenarioError):
            scenario.receive_exact(Stream([b"ab"]), 4)

    def test_udp_progress_rejects_stale_echoes_and_nonadvancing_payload(self):
        state = {"udp_bytes": {"wg1": 10, "wg2": 10},
                 "udp_last_success": {"wg1": 10, "wg2": 10}, "errors": []}
        progress = scenario.UDPProgress()
        progress.observe(state, now=10)
        state["udp_last_success"] = {"wg1": 13, "wg2": 13}
        with self.assertRaisesRegex(scenario.ScenarioError, "stopped advancing"):
            progress.observe(state, now=13)
        state["udp_bytes"] = {"wg1": 20, "wg2": 20}
        state["udp_last_success"] = {"wg1": 10, "wg2": 10}
        with self.assertRaisesRegex(scenario.ScenarioError, "stale UDP"):
            scenario.UDPProgress().observe(state, now=13)

    def test_drain_requires_zero_tcp_and_two_fresh_live_udp_sessions(self):
        with tempfile.TemporaryDirectory(prefix="memory-fixture-unit-") as directory, patch.object(scenario.time, "monotonic", return_value=12):
            fixture = scenario.Fixture(SimpleNamespace(), Path(directory), scenario.Cleanup())
            state = Path(directory) / "server-active.json"
            state.write_text(json.dumps({"tcp_connections": 0}))
            fixture.current_traffic = Path(directory) / "traffic.json"
            traffic = {"connected": 0, "udp_bytes": {"wg1": 10, "wg2": 10},
                       "udp_last_success": {tag: 10 for tag in scenario.TAGS}, "errors": []}
            fixture.current_traffic.write_text(json.dumps(traffic))
            stats = {"outbounds": [{"tag": "wg1", "active": 1}, {"tag": "wg2", "active": 1}]}
            self.assertTrue(fixture.drained(stats))
            stats["outbounds"].append({"tag": "direct", "active": 1})
            with self.assertRaisesRegex(scenario.ScenarioError, "exactly the two"):
                fixture.drained(stats)
            stats["outbounds"].pop()
            state.write_text(json.dumps({"tcp_connections": 1}))
            with self.assertRaises(scenario.ScenarioError):
                fixture.drained(stats)
            state.write_text(json.dumps({"tcp_connections": 0}))
            stats["outbounds"][0]["active"] = 2
            with self.assertRaises(scenario.ScenarioError):
                fixture.drained(stats)
            # A stale/closed UDP mapping must not mask a leaked TCP entry even
            # when the API still reports exactly one session per tunnel.
            stats["outbounds"][0]["active"] = 1
            traffic["udp_last_success"]["wg1"] = 0
            fixture.current_traffic.write_text(json.dumps(traffic))
            with self.assertRaisesRegex(scenario.ScenarioError, "stale UDP"):
                fixture.drained(stats)

    def test_drain_validates_udp_timestamps_at_freshness_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="memory-fixture-clock-") as directory:
            fixture = scenario.Fixture(SimpleNamespace(), Path(directory), scenario.Cleanup())
            (Path(directory) / "server-active.json").write_text(json.dumps({"tcp_connections": 0}))
            fixture.current_traffic = Path(directory) / "traffic.json"
            stats = {"outbounds": [{"tag": tag, "active": 1} for tag in scenario.TAGS]}
            cases = ((0.5, 0.5, True), (12, 10, True), (12, 12, True),
                     (0.5, 0, False), (1.5, True, False), (12, 12.1, False),
                     (12, float("nan"), False), (12, "12", False), (12, None, False))
            for now, last, accepted in cases:
                with self.subTest(now=now, last=last):
                    fixture.udp_progress = scenario.UDPProgress()
                    fixture.current_traffic.write_text(json.dumps({
                        "connected": 0, "udp_bytes": {tag: 10 for tag in scenario.TAGS},
                        "udp_last_success": {tag: last for tag in scenario.TAGS}, "errors": []}))
                    with patch.object(scenario.time, "monotonic", return_value=now):
                        if accepted:
                            self.assertTrue(fixture.drained(stats))
                        else:
                            with self.assertRaises(scenario.ScenarioError):
                                fixture.drained(stats)

    def test_failed_run_preserves_artifacts_after_removing_local_ipc(self):
        with tempfile.TemporaryDirectory(prefix="memory-result-unit-") as directory:
            output = Path(directory) / "result.json"
            owned = []
            def fail_setup(fixture):
                owned.append(fixture.directory)
                self.assertNotEqual(fixture.directory.parent, output.parent)
                raise scenario.ScenarioError("controlled startup failure")
            args = SimpleNamespace(output=str(output), variant="baseline", scenario="wireguard", run=1)
            with patch.object(scenario.Fixture, "setup", fail_setup), patch.object(scenario.Fixture, "failure_snapshot"):
                with self.assertRaisesRegex(scenario.ScenarioError, "controlled startup failure"):
                    scenario.run(args)
            self.assertFalse(owned[0].exists())
            self.assertIn("controlled startup failure", json.loads(output.read_text())["error"])
            self.assertTrue((output.with_suffix(".artifacts") / "failure.log").is_file())
            self.assertTrue((output.with_suffix(".artifacts") / "stats.json").is_file())

    def test_copy_failure_retains_original_evidence(self):
        with tempfile.TemporaryDirectory(prefix="memory-result-unit-") as directory:
            output, owned = Path(directory) / "result.json", []
            def fail_setup(fixture):
                owned.append(fixture.directory)
                self.addCleanup(scenario.shutil.rmtree, fixture.directory)
                raise scenario.ScenarioError("controlled startup failure")
            args = SimpleNamespace(output=str(output), variant="baseline", scenario="wireguard", run=1)
            with patch.object(scenario.Fixture, "setup", fail_setup), patch.object(scenario.Fixture, "failure_snapshot"):
                with patch.object(scenario.shutil, "copytree", side_effect=OSError("artifact destination unavailable")):
                    with self.assertRaises(scenario.ScenarioError):
                        scenario.run(args)
            report = json.loads(output.read_text())
            self.assertEqual(report["retained_artifacts"], str(owned[0]))
            self.assertIn("artifact destination unavailable", report["cleanup_error"])
            self.assertTrue((owned[0] / "failure.log").is_file())

    def test_cleanup_runs_all_callbacks_and_reports_failure(self):
        calls = []
        def fail():
            calls.append("failed")
            raise RuntimeError("owned resource remains")
        cleanup = scenario.Cleanup()
        cleanup.add(lambda: calls.append("first"))
        cleanup.add(fail)
        with self.assertRaises(scenario.ScenarioError):
            cleanup.close()
        self.assertEqual(calls, ["failed", "first"])
        cleanup.close()


if __name__ == "__main__":
    unittest.main()

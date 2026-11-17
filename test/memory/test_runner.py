"""Executable ownership and lifecycle regressions; Docker integration runs separately."""
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).with_name("run.sh").read_text()


def function(name):
    start = RUNNER.index(name + "() {\n")
    return RUNNER[start:RUNNER.index("\n}\n", start) + 3]


class EvidenceOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.root = None
        self.addCleanup(self.remove_fixture)
        self.root = Path(tempfile.mkdtemp(prefix="keenproxy-handoff-"))

    def remove_fixture(self):
        if self.root is None:
            return
        shutil.rmtree(self.root)
        self.assertFalse(self.root.exists())

    def handoff(self, *roots, uid=None, gid=None):
        script = subprocess.check_output(
            ["sh", "-c", function("evidence_handoff_script") + "\nevidence_handoff_script"],
            text=True,
        )
        return subprocess.run(
            [sys.executable, "-c", script, str(os.getuid() if uid is None else uid),
             str(os.getgid() if gid is None else gid), *map(str, roots)],
            capture_output=True, text=True,
        )

    def test_private_exports_and_rescued_tmp_preserve_modes_without_following_links(self):
        outside = self.root / "outside"
        outside.write_text("not exported")
        original = outside.stat()
        roots = [self.root / "results", self.root / "container-tmp"]
        for root in roots:
            root.mkdir(mode=0o700)
            nested = root / "private"
            nested.mkdir(mode=0o700)
            artifact = nested / "evidence.json"
            artifact.write_text("evidence")
            artifact.chmod(0o600)
            (nested / "outside").symlink_to(outside)
            (nested / "cycle").symlink_to(root, target_is_directory=True)
        result = self.handoff(*roots)
        self.assertEqual(result.returncode, 0, result.stderr)
        for root in roots:
            self.assertEqual(stat.S_IMODE((root / "private").stat().st_mode), 0o700)
            artifact = root / "private/evidence.json"
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(artifact.read_text(), "evidence")
        self.assertEqual(outside.stat(), original)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to exercise a foreign host UID/GID")
    def test_root_exports_are_readable_by_the_invoking_nonroot_user(self):
        uid, gid = 23456, 23457
        # The fixture parent is not exported; allow the child user to reach its owned tree.
        self.root.chmod(0o711)
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        artifact = evidence / "stress.json"
        artifact.write_text("private evidence")
        artifact.chmod(0o600)
        outside = self.root / "outside"
        outside.write_text("not exported")
        (evidence / "outside").symlink_to(outside)
        result = self.handoff(evidence, uid=uid, gid=gid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((artifact.stat().st_uid, artifact.stat().st_gid), (uid, gid))
        self.assertEqual(outside.stat().st_uid, 0)
        self.assertEqual((evidence / "outside").lstat().st_uid, uid)
        read = subprocess.run(
            [sys.executable, "-c", "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())", str(artifact)],
            user=uid, group=gid, extra_groups=[], capture_output=True, text=True,
        )
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(read.stdout.strip(), "private evidence")

    def test_hardlink_and_symlink_roots_fail_closed(self):
        outside = self.root / "outside"
        outside.write_text("outside")
        evidence = self.root / "evidence"
        evidence.mkdir()
        os.link(outside, evidence / "hardlink")
        result = self.handoff(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hard-linked", result.stderr)
        link = self.root / "root-link"
        link.symlink_to(evidence, target_is_directory=True)
        self.assertNotEqual(self.handoff(link).returncode, 0)

    def test_fifo_and_socket_evidence_are_rejected_without_handoff(self):
        for kind in ("fifo", "socket"):
            with self.subTest(kind=kind):
                evidence = self.root / kind
                evidence.mkdir(mode=0o700)
                special = evidence / "special"
                if kind == "fifo":
                    os.mkfifo(special, 0o600)
                    result = self.handoff(evidence)
                else:
                    with socket.socket(socket.AF_UNIX) as sock:
                        sock.bind(str(special))
                        result = self.handoff(evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("special-file evidence", result.stderr)
                self.assertEqual(special.lstat().st_uid, os.getuid())
                self.assertEqual(evidence.stat().st_uid, os.getuid())


class RunnerLifecycleTests(unittest.TestCase):
    def shell(self, definitions, body):
        return subprocess.run(["sh", "-c", "set -eu\n" + definitions + "\n" + body],
                              capture_output=True, text=True)

    def helper_definitions(self):
        return "\n".join(function(name) for name in (
            "evidence_handoff_script", "normalize_evidence",
            "remove_owned_handoff", "confirm_absent",
        )) + """
docker() {
    case "$1 $2" in
        'container inspect')
            [ -f "$OUT/helper-created" ] || return 1
            [ "$FAULT" != owner ] || return 6
            echo mine ;;
        'container ls')
            [ "$FAULT" != absence ] || return 8
            [ ! -f "$OUT/helper-created" ] || echo helper ;;
        'create --name')
            printf '%s\\n' "$@" >"$OUT/create-args"
            touch "$OUT/helper-created"
            return "$CREATE_STATUS" ;;
        'start -a') return "$START_STATUS" ;;
        'inspect --format')
            [ "$FAULT" != state ] || return 5
            printf '%s\\n' "$STATE" ;;
        'rm -f')
            touch "$OUT/helper-removal-attempted"
            [ "$FAULT" != remove ] || return 7
            rm "$OUT/helper-created"
            echo removed >"$OUT/helper-removed" ;;
        *) echo "unexpected Docker call: $*" >&2; return 99 ;;
    esac
}
"""

    def test_handoff_helper_is_removed_after_success_and_each_failure(self):
        definitions = self.helper_definitions()
        good_state = '{"Status":"exited","ExitCode":0,"OOMKilled":false}'
        bad_state = '{"Status":"running","ExitCode":0,"OOMKilled":false}'
        cases = [(0, 0, good_state, "", 0, 0), (7, 0, good_state, "", 1, 0),
                 (0, 9, good_state, "", 1, 0), (0, 0, bad_state, "", 1, 0),
                 (0, 0, good_state, "state", 1, 0),
                 (0, 0, good_state, "owner", 1, 1),
                 (0, 0, good_state, "remove", 1, 1),
                 (0, 0, good_state, "absence", 1, 1)]
        for create, start, state, fault, expected, retained in cases:
            with self.subTest(create=create, start=start, state=state, fault=fault):
                with tempfile.TemporaryDirectory(prefix="keenproxy-helper-") as out:
                    Path(out, "results").mkdir()
                    Path(out, "container-tmp").mkdir()
                    body = f"""
OUT={out}; OWNER=mine; HANDOFF_CONTAINER=owned-handoff; HANDOFF_OWNED=0
EVIDENCE_DIRTY=1; EVIDENCE_QUIESCENT=1; IMAGE_ID=sha256:immutable; HOST_UID=1234; HOST_GID=5678
CREATE_STATUS={create}; START_STATUS={start}; STATE='{state}'; FAULT='{fault}'
code=0
normalize_evidence || code=$?
echo "$code $HANDOFF_OWNED $EVIDENCE_DIRTY"
"""
                    result = self.shell(definitions, body)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), f"{expected} {retained} {expected}")
                    removed = fault not in ("owner", "remove")
                    self.assertEqual(Path(out, "helper-removed").exists(), removed)
                    self.assertEqual(Path(out, "helper-created").exists(), not removed)
                    self.assertEqual(Path(out, "helper-removal-attempted").exists(), fault != "owner")
                    args = Path(out, "create-args").read_text()
                    self.assertIn(f"type=bind,src={out}/results,dst=/evidence/results", args)
                    self.assertIn(f"type=bind,src={out}/container-tmp,dst=/evidence/container-tmp", args)
                    self.assertNotIn("/binaries", args)
                    self.assertNotIn("/fixture", args)
                    self.assertIn("1234\n5678\n", args)


    def test_handoff_failure_preserves_original_exit_status(self):
        definitions = function("cleanup") + """
remove_owned_container() { echo rescue-remove; }
remove_owned_handoff() { :; }
normalize_evidence() { echo handoff-failed; return 1; }
remove_owned_image() { echo image-remove; }
"""
        for original, expected in [(0, 1), (42, 42), (130, 130)]:
            with self.subTest(original=original), tempfile.TemporaryDirectory(prefix="keenproxy-cleanup-") as out:
                body = f'OUT={out}; MODE=stress; CONTAINER_OWNED=1; IMAGE_OWNED=1; trap cleanup EXIT; exit {original}'
                result = self.shell(definitions, body)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual((Path(out) / "exit-code").read_text().strip(), str(expected))

    def test_helper_api_failures_remain_tracked_through_cleanup(self):
        definitions = self.helper_definitions() + function("cleanup") + """
remove_owned_image() {
    printf '%s\\n' "$HANDOFF_OWNED" >"$OUT/cleanup-helper-owned"
    touch "$OUT/image-removal-attempted"
}
"""
        for fault in ("state", "owner", "remove", "absence"):
            for original, expected in ((0, 1), (42, 42)):
                with self.subTest(fault=fault, original=original):
                    with tempfile.TemporaryDirectory(prefix="keenproxy-api-failure-") as out:
                        Path(out, "results").mkdir()
                        Path(out, "container-tmp").mkdir()
                        body = f"""
OUT={out}; OWNER=mine; HANDOFF_CONTAINER=owned-handoff; HANDOFF_OWNED=0
CONTAINER_OWNED=0; IMAGE_OWNED=1; MODE=stress
EVIDENCE_DIRTY=1; EVIDENCE_QUIESCENT=1; IMAGE_ID=sha256:immutable
HOST_UID=1234; HOST_GID=5678; CREATE_STATUS=0; START_STATUS=0; FAULT={fault}
STATE='{{"Status":"exited","ExitCode":0,"OOMKilled":false}}'
trap cleanup EXIT
normalize_evidence || :
exit {original}
"""
                        result = self.shell(definitions, body)
                        self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertEqual(Path(out, "exit-code").read_text().strip(), str(expected))
                        self.assertTrue(Path(out, "image-removal-attempted").exists())
                        retained = fault != "state"
                        self.assertEqual(Path(out, "cleanup-helper-owned").read_text().strip(), str(int(retained)))
                        self.assertEqual(Path(out, "helper-created").exists(), fault in ("owner", "remove"))
                        self.assertEqual(Path(out, "helper-removal-attempted").exists(), fault != "owner")

    def test_release_requires_fresh_exited_state(self):
        definitions = function("confirm_workload_exited") + """
docker() {
    [ "$STATE" != unavailable ] || return 7
    printf '%s\\n' "$STATE"
}
"""
        for state, expected in (("exited false", 0), ("running true", 1), ("unavailable", 1)):
            with self.subTest(state=state):
                result = self.shell(definitions, f"""
CONTAINER=owned; EVIDENCE_QUIESCENT=1; STATE='{state}'; code=0
confirm_workload_exited || code=$?
printf '%s %s\\n' "$code" "$EVIDENCE_QUIESCENT"
""")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), f"{expected} {int(not expected)}")

    def test_unconfirmed_workload_blocks_handoff_but_not_cleanup(self):
        definitions = "\n".join(function(name) for name in (
            "cleanup", "remove_owned_container", "remove_owned_handoff",
            "normalize_evidence", "confirm_absent",
        )) + """
remove_owned_image() {
    printf '%s %s\\n' "$CONTAINER_OWNED" "$EVIDENCE_QUIESCENT" >"$OUT/cleanup-state"
    touch "$OUT/image-removal-attempted"
}
docker() {
    printf '%s\\n' "$1 $2" >>"$OUT/docker-calls"
    case "$1 $2" in
        'container inspect')
            [ "$FAULT" != owner ] || return 7
            echo mine ;;
        'container ls')
            [ "$FAULT" != absence ] || return 8
            [ -f "$OUT/workload-removed" ] || echo workload ;;
        'stop --time') [ "$FAULT" != stop-remove ] ;;
        'cp owned:/tmp/.') touch "$OUT/rescue-attempted" ;;
        'rm -f')
            [ "$FAULT" != remove ] && [ "$FAULT" != stop-remove ] || return 9
            touch "$OUT/workload-removed" ;;
        *) echo "unexpected Docker call: $*" >&2; return 99 ;;
    esac
}
"""
        for fault in ("owner", "remove", "absence", "stop-remove"):
            for original, expected in ((0, 1), (42, 42)):
                with self.subTest(fault=fault, original=original):
                    with tempfile.TemporaryDirectory(prefix="keenproxy-quiescence-") as out:
                        body = f"""
OUT={out}; OWNER=mine; CONTAINER=owned; CONTAINER_OWNED=1
HANDOFF_OWNED=0; IMAGE_OWNED=1; MODE=stress; EVIDENCE_DIRTY=1
EVIDENCE_QUIESCENT=1; FAULT={fault}
trap cleanup EXIT
exit {original}
"""
                        result = self.shell(definitions, body)
                        self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertEqual(Path(out, "exit-code").read_text().strip(), str(expected))
                        self.assertEqual(Path(out, "cleanup-state").read_text().strip(), "1 0")
                        self.assertIn("without proof", result.stderr)
                        self.assertTrue(Path(out, "image-removal-attempted").exists())
                        calls = Path(out, "docker-calls").read_text()
                        self.assertNotIn("create ", calls)
                        if fault != "owner":
                            self.assertIn("rm -f", calls)
                            self.assertTrue(Path(out, "rescue-attempted").exists())


if __name__ == "__main__":
    unittest.main()

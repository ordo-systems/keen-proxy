"""Exercise the workflow's logging boundary with real command/logger processes."""
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
PAYLOAD = bytes(range(256)) * 256 + b"terminal failure\n"
LOGGER = """import os
from pathlib import Path
import socket
import sys
payload = sys.stdin.buffer.read()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
    channel.settimeout(5)
    channel.connect(os.environ['TEE_CONTROL'])
    channel.sendall(b'r')
    if channel.recv(1) != b'f':
        raise SystemExit(98)
    Path(sys.argv[1]).write_bytes(payload)
    channel.sendall(b'd')
raise SystemExit(int(os.environ['TEE_STATUS']))
"""


def logging_preamble():
    """Execute the actual workflow setup, without starting historical builds."""
    step = WORKFLOW.read_text().split(
        "      - name: Verify and build historical source without AWG certification\n", 1)[1]
    body = step.split("        run: |\n", 1)[1]
    return textwrap.dedent(body.split("          set -x\n", 1)[0])


@unittest.skipUnless(sys.platform == "linux", "release workflow runs on Linux Bash")
class ReleaseLoggingTests(unittest.TestCase):
    def setUp(self):
        self.root = None
        self.addCleanup(self.remove_fixture)
        self.root = Path(tempfile.mkdtemp(prefix="kp-release-log-"))

    def remove_fixture(self):
        if self.root is not None:
            shutil.rmtree(self.root)
            self.assertFalse(self.root.exists())

    def run_logged(self, command_status, logger_status):
        case = self.root / (str(command_status) + "-" + str(logger_status))
        evidence = case / ".agents-work/release-legacy/owned-1"
        evidence.mkdir(parents=True)
        helper = case / "logger.py"
        helper.write_text(LOGGER)
        address = str(case / "tee.sock")
        env = dict(os.environ, GITHUB_RUN_ID="owned", GITHUB_RUN_ATTEMPT="1",
                   TEE_CONTROL=address, TEE_STATUS=str(logger_status))
        logger = "tee() { exec " + shlex.join([sys.executable, str(helper)]) + ' "$@"; }\n'
        command = shlex.join([sys.executable, "-c",
            "import sys; sys.stdout.buffer.write(bytes(range(256))*256); "
            "sys.stdout.flush(); sys.stderr.buffer.write(b'terminal failure\\n'); "
            "sys.stderr.flush(); sys.exit(" + str(command_status) + ")"])
        process, connection, released = None, None, False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, (case / "console.log").open("wb") as console:
            listener.settimeout(5)
            listener.bind(address)
            listener.listen(1)
            try:
                process = subprocess.Popen(
                    ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
                     logger + logging_preamble() + "\n" + command], cwd=case, env=env,
                    stdout=console, stderr=subprocess.STDOUT,
                    start_new_session=True)
                connection, _ = listener.accept()
                connection.settimeout(5)
                self.assertEqual(connection.recv(1), b"r")
                self.assertIsNone(process.poll(), "workflow exited before the logger flushed")
                connection.sendall(b"f")
                released = True
                self.assertEqual(connection.recv(1), b"d")
                code = process.wait(timeout=5)
                self.assertEqual((evidence / "verification.log").read_bytes(), PAYLOAD)
                self.assertEqual((evidence / "exit-code").read_text().strip(), str(code))
                return code
            except Exception:
                console.flush()
                print((case / "console.log").read_text(errors="replace"), file=sys.stderr)
                raise
            finally:
                if connection is not None:
                    try:
                        if not released:
                            connection.sendall(b"f")
                        while connection.recv(1024):
                            pass
                    except OSError:
                        pass
                    connection.close()
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)

    def test_success_and_failure_wait_for_the_complete_log(self):
        for code in (0, 42):
            with self.subTest(command_status=code):
                self.assertEqual(self.run_logged(code, 0), code)

    def test_logger_failure_fails_success_without_replacing_primary_error(self):
        for code, expected in ((0, 17), (42, 42)):
            with self.subTest(command_status=code):
                self.assertEqual(self.run_logged(code, 17), expected)


if __name__ == "__main__":
    unittest.main()

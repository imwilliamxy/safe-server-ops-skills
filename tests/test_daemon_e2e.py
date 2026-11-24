"""End-to-end dual Unix Domain Socket daemon + opsctl + ops-approve CLI tests."""

from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from safe_server_ops.approve_cli import main as approve_main
from safe_server_ops.audit import AuditLogger
from safe_server_ops.cli import main as opsctl_main
from safe_server_ops.config import load_policy, load_server_profiles
from safe_server_ops.daemon import OpsDaemon, OpsEngine
from safe_server_ops.executors.ssh_exec import CommandResult
from safe_server_ops.protocol import send_request


class DualSocketE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        key = self.root / "id_ops"
        key.write_text("key", encoding="utf-8")

        env = self.root / ".ssh-servers.env"
        env.write_text(
            f"[prod-web]\nHOST=198.51.100.99\nUSER=ops_hidden\nPORT=22\nKEY_FILE={key}\n",
            encoding="utf-8",
        )
        pol = self.root / "policy.yaml"
        pol.write_text(
            """
global:
  gate_mode: true
servers:
  prod-web:
    docker:
      allowed_containers:
        - web-app
""",
            encoding="utf-8",
        )

        self.client_sock = self.root / "ops.sock"
        self.admin_sock = self.root / "admin.sock"
        self.audit_path = self.root / "audit.jsonl"

        def mock_runner(argv: list[str], _stdin: str | None, _timeout: int) -> CommandResult:
            cmd = argv[-1]
            if cmd.startswith("docker-status"):
                return CommandResult(0, "/web-app\trunning\thealthy\t0\tnow\n", "")
            if cmd.startswith("docker-restart"):
                return CommandResult(0, "web-app\n", "")
            if cmd.startswith("logs-docker"):
                return CommandResult(0, "boot ok on 198.51.100.99\n", "")
            return CommandResult(0, "", "")

        profiles = load_server_profiles(env)
        policy = load_policy(pol, known_servers=set(profiles.keys()))
        engine = OpsEngine(
            profiles=profiles,
            policy=policy,
            audit=AuditLogger(self.audit_path),
            runner=mock_runner,
            post_restart_wait=0.0,
        )
        self.daemon = OpsDaemon(
            engine=engine,
            client_socket=self.client_sock,
            admin_socket=self.admin_sock,
            client_mode=0o600,
        )
        self.daemon.start_background()

    def tearDown(self) -> None:
        self.daemon.stop()
        self._tmp.cleanup()

    def _run_cli(self, fn, argv: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = fn(argv)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_dual_socket_permissions_and_full_cli_flow(self) -> None:
        # Admin socket must strictly be 0600
        admin_mode = stat.S_IMODE(self.admin_sock.stat().st_mode)
        self.assertEqual(admin_mode, 0o600)

        # 1. opsctl capabilities
        rc, out, _ = self._run_cli(opsctl_main, ["--socket", str(self.client_sock), "--json", "capabilities"])
        self.assertEqual(rc, 0)
        caps = json.loads(out)
        self.assertTrue(caps["ok"])
        self.assertNotIn("198.51.100.99", out)

        # 2. opsctl docker restart-plan
        rc, out, _ = self._run_cli(
            opsctl_main,
            [
                "--socket",
                str(self.client_sock),
                "--json",
                "docker",
                "restart-plan",
                "prod-web",
                "web-app",
                "--reason",
                "e2e test",
            ],
        )
        self.assertEqual(rc, 0)
        token = json.loads(out)["data"]["plan_token"]

        # 3. Direct attempt to approve via client socket MUST be rejected
        bad_approve = send_request(self.client_sock, "admin.approve", {"plan_token": token})
        self.assertFalse(bad_approve["ok"])

        # 4. Human lists & approves via ops-approve on admin socket
        rc, out, _ = self._run_cli(approve_main, ["--admin-socket", str(self.admin_sock), "--list"])
        self.assertEqual(rc, 0)
        self.assertIn(token, out)

        rc, out, _ = self._run_cli(
            approve_main, ["--admin-socket", str(self.admin_sock), "approve", token]
        )
        self.assertEqual(rc, 0)
        self.assertIn("APPROVED", out)

        # 5. opsctl applies approved plan
        rc, out, _ = self._run_cli(
            opsctl_main,
            ["--socket", str(self.client_sock), "--json", "docker", "restart-apply", token],
        )
        self.assertEqual(rc, 0)
        applied = json.loads(out)
        self.assertTrue(applied["ok"])
        self.assertNotIn("198.51.100.99", applied["data"]["startup_logs"])

        # 6. Audit log recorded actions without leaking host/user
        audit_text = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("docker.restart_apply", audit_text)
        self.assertIn("admin.approve", audit_text)
        self.assertNotIn("198.51.100.99", audit_text)
        self.assertNotIn("ops_hidden", audit_text)


if __name__ == "__main__":
    unittest.main()

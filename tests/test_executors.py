"""Tests for logs, Docker, rsync (symlinks/TOCTOU/delete-fuse), and config (validate/rollback) executors."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from safe_server_ops.audit import AuditLogger
from safe_server_ops.config import load_policy, load_server_profiles
from safe_server_ops.daemon import OpsEngine
from safe_server_ops.executors.ssh_exec import CommandResult


class ExecutorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.key_ops = self.root / "id_ops"
        self.key_sync = self.root / "id_sync"
        self.key_ops.write_text("ops-key", encoding="utf-8")
        self.key_sync.write_text("sync-key", encoding="utf-8")

        self.staging = self.root / "staging"
        self.staging.mkdir()
        (self.staging / "index.php").write_text("<?php echo 'v1';\n", encoding="utf-8")
        (self.staging / "style.css").write_text("body { color: #111; }\n", encoding="utf-8")

        self.env_file = self.root / ".ssh-servers.env"
        self.env_file.write_text(
            f"""
[prod-web]
HOST=203.0.113.77
USER=prod_secret_user
PORT=2200
KEY_FILE={self.key_ops}
SYNC_KEY_FILE={self.key_sync}
""",
            encoding="utf-8",
        )

        self.policy_file = self.root / "policy.yaml"
        self.policy_file.write_text(
            f"""
global:
  plan_ttl_seconds: 180
  max_output_bytes: 16384
  gate_mode: true
  strict_host_key_checking: "yes"

servers:
  prod-web:
    description: "Main prod node"
    logs:
      nginx-err:
        type: file
        path: /var/log/nginx/error.log
        max_lines: 50
    docker:
      allowed_containers:
        - web-app
    configs:
      nginx-site:
        path: /etc/nginx/conf.d/app.conf
        backup_dir: /var/backups/ai-ops/nginx
        validator: nginx_test
        reload_action: nginx_reload
        redact_patterns:
          - '(?i)api_secret=[^\s;]+'

sync_targets:
  plugin-release:
    server: prod-web
    direction: push
    local_base: {self.staging}
    remote_base: /var/www/html/wp-content/plugins/my-plugin
    use_rrsync: true
    allow_delete: false
    max_files: 50
    max_size_mb: 10
  strict-delete-target:
    server: prod-web
    direction: push
    local_base: {self.staging}
    remote_base: /var/www/html/static
    allow_delete: true
    max_delete_files: 1
    max_files: 50
    max_size_mb: 10
""",
            encoding="utf-8",
        )

        self.calls: list[tuple[list[str], str | None]] = []
        self.remote_config_content = (
            "server {\n"
            "  listen 80;\n"
            "  proxy_set_header X-Secret api_secret=topsecret_42;\n"
            "}\n"
        )
        self.validator_should_fail = False
        self.reload_should_fail = False
        self.rsync_preview_stdout = ">f+++++++++ index.php\n>f.st...... style.css\n"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _mock_runner(self, argv: list[str], stdin_data: str | None, _timeout: int) -> CommandResult:
        self.calls.append((argv, stdin_data))
        if argv[0] == "rsync":
            if "--dry-run" in argv:
                return CommandResult(0, self.rsync_preview_stdout, "")
            return CommandResult(0, ">f+++++++++ index.php\nNumber of files transferred: 2\n", "")

        # SSH invocation: last arg is shlex-joined remote command
        remote_cmd = argv[-1]
        if remote_cmd.startswith("logs-file "):
            return CommandResult(
                0,
                "INFO boot ok\nERROR upstream 203.0.113.77 timeout for prod_secret_user\nINFO done\n",
                "",
            )
        if remote_cmd.startswith("docker-status "):
            return CommandResult(0, "/web-app\trunning\thealthy\t0\t2026-11-24T00:00:00Z\n", "")
        if remote_cmd.startswith("docker-restart "):
            return CommandResult(0, "web-app\n", "")
        if remote_cmd.startswith("logs-docker "):
            return CommandResult(0, "Started web-app on 203.0.113.77\n", "")
        if remote_cmd.startswith("config-read "):
            return CommandResult(0, self.remote_config_content, "")
        if remote_cmd.startswith("config-validate "):
            if self.validator_should_fail:
                return CommandResult(1, "", "nginx: [emerg] unexpected token in /etc/nginx/conf.d/app.conf")
            return CommandResult(0, "nginx: configuration file ok\n", "")
        if remote_cmd.startswith("config-apply "):
            if self.reload_should_fail:
                return CommandResult(
                    1,
                    json.dumps({"backup_id": "nginx-site.20261124.bak", "reloaded": False, "rolled_back": True}),
                    "nginx reload failed",
                )
            assert stdin_data is not None
            self.remote_config_content = stdin_data
            return CommandResult(
                0,
                json.dumps({"backup_id": "nginx-site.20261124.bak", "reloaded": True, "rolled_back": False}),
                "",
            )
        if remote_cmd.startswith("config-backups "):
            return CommandResult(0, "nginx-site.20261124.bak\n", "")
        if remote_cmd.startswith("config-rollback "):
            return CommandResult(0, "Rolled back nginx-site to nginx-site.20261124.bak\n", "")
        return CommandResult(1, "", f"Unexpected command: {remote_cmd}")

    def _make_engine(self) -> OpsEngine:
        profiles = load_server_profiles(self.env_file)
        policy = load_policy(self.policy_file, known_servers=set(profiles.keys()))
        return OpsEngine(
            profiles=profiles,
            policy=policy,
            audit=AuditLogger(self.root / "audit.jsonl"),
            runner=self._mock_runner,
            post_restart_wait=0.0,
        )

    def test_capabilities_never_leak_credentials_or_paths(self) -> None:
        engine = self._make_engine()
        resp = engine.handle_client_request("capabilities", {})
        self.assertTrue(resp["ok"])
        serialized = json.dumps(resp)
        for hidden in ("203.0.113.77", "prod_secret_user", str(self.key_ops), "/var/www/html"):
            self.assertNotIn(hidden, serialized)
        self.assertIn("prod-web", resp["data"]["servers"])
        self.assertIn("plugin-release", resp["data"]["sync_targets"])

    def test_logs_clamping_local_keyword_filter_and_redaction(self) -> None:
        engine = self._make_engine()
        resp = engine.handle_client_request(
            "logs",
            {"server": "prod-web", "log_id": "nginx-err", "lines": 9999, "keyword": "ERROR"},
        )
        self.assertTrue(resp["ok"])
        data = resp["data"]
        self.assertEqual(data["lines_requested"], 50)
        self.assertIn("ERROR upstream", data["content"])
        self.assertNotIn("INFO boot ok", data["content"])
        self.assertNotIn("203.0.113.77", data["content"])
        self.assertNotIn("prod_secret_user", data["content"])

        # Non-whitelisted log rejected
        bad = engine.handle_client_request("logs", {"server": "prod-web", "log_id": "shadow"})
        self.assertFalse(bad["ok"])

    def test_docker_two_phase_restart(self) -> None:
        engine = self._make_engine()
        plan_resp = engine.handle_client_request(
            "docker.restart_plan",
            {"server": "prod-web", "target": "web-app", "reason": "Memory spike"},
        )
        self.assertTrue(plan_resp["ok"])
        token = plan_resp["data"]["plan_token"]

        # Unapproved apply must fail
        unapproved = engine.handle_client_request("docker.restart_apply", {"plan_token": token})
        self.assertFalse(unapproved["ok"])

        # Human approves on admin path
        ap = engine.handle_admin_request("admin.approve", {"plan_token": token, "actor": "human:bob"})
        self.assertTrue(ap["ok"])

        # Approved apply runs restart and returns redacted startup logs
        applied = engine.handle_client_request("docker.restart_apply", {"plan_token": token})
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["data"]["exit_code"], 0)
        self.assertNotIn("203.0.113.77", applied["data"]["startup_logs"])
        self.assertIn("Started web-app", applied["data"]["startup_logs"])

    def test_rsync_escaping_symlink_rejected(self) -> None:
        outside = self.root / "outside_secret.txt"
        outside.write_text("SECRET", encoding="utf-8")
        os.symlink(outside, self.staging / "leak.txt")

        engine = self._make_engine()
        resp = engine.handle_client_request("rsync.preview", {"target": "plugin-release"})
        self.assertFalse(resp["ok"])
        self.assertIn("symlink", resp["error"].lower())

    def test_rsync_delete_circuit_breaker(self) -> None:
        self.rsync_preview_stdout = "*deleting a.php\n*deleting b.php\n"
        engine = self._make_engine()
        resp = engine.handle_client_request("rsync.preview", {"target": "strict-delete-target"})
        self.assertFalse(resp["ok"])
        self.assertIn("circuit breaker", resp["error"].lower())

    def test_rsync_toctou_tampering_blocked_and_clean_apply_succeeds(self) -> None:
        engine = self._make_engine()
        prev = engine.handle_client_request("rsync.preview", {"target": "plugin-release"})
        self.assertTrue(prev["ok"])
        token = prev["data"]["plan_token"]
        engine.handle_admin_request("admin.approve", {"plan_token": token, "actor": "human:bob"})

        # Tamper with staging file AFTER preview & approval!
        (self.staging / "index.php").write_text("<?php system($_GET['x']);\n", encoding="utf-8")
        tampered = engine.handle_client_request("rsync.apply", {"plan_token": token})
        self.assertFalse(tampered["ok"])
        self.assertIn("toctou", tampered["error"].lower())

        # Re-preview cleanly and apply without tampering
        prev2 = engine.handle_client_request("rsync.preview", {"target": "plugin-release"})
        self.assertTrue(prev2["ok"])
        tok2 = prev2["data"]["plan_token"]
        engine.handle_admin_request("admin.approve", {"plan_token": tok2, "actor": "human:bob"})
        applied = engine.handle_client_request("rsync.apply", {"plan_token": tok2})
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["data"]["exit_code"], 0)
        # Ensure rrsync mode targeted "." rather than exposing remote_base
        rsync_argv = [c[0] for c in self.calls if c[0][0] == "rsync"][-1]
        self.assertTrue(rsync_argv[-1].endswith(":."))

    def test_config_full_lifecycle_validation_and_rollback(self) -> None:
        engine = self._make_engine()
        read_resp = engine.handle_client_request(
            "config.read", {"server": "prod-web", "config_id": "nginx-site"}
        )
        self.assertTrue(read_resp["ok"])
        base_sha = read_resp["data"]["base_sha256"]
        masked = read_resp["data"]["content"]
        self.assertNotIn("topsecret_42", masked)
        self.assertIn("{{REDACTED_SECRET_1}}", masked)

        draft = masked.replace("listen 80;", "listen 443 ssl;")

        # 1. Validator failure blocks plan issuance
        self.validator_should_fail = True
        bad_plan = engine.handle_client_request(
            "config.plan",
            {
                "server": "prod-web",
                "config_id": "nginx-site",
                "draft_content": draft,
                "base_sha256": base_sha,
                "reason": "Enable TLS",
            },
        )
        self.assertFalse(bad_plan["ok"])
        self.assertNotIn("/etc/nginx/conf.d/app.conf", bad_plan["error"])

        # 2. Valid plan passes validation & produces redacted diff
        self.validator_should_fail = False
        plan_resp = engine.handle_client_request(
            "config.plan",
            {
                "server": "prod-web",
                "config_id": "nginx-site",
                "draft_content": draft,
                "base_sha256": base_sha,
                "reason": "Enable TLS",
            },
        )
        self.assertTrue(plan_resp["ok"])
        self.assertNotIn("topsecret_42", plan_resp["data"]["diff"])
        self.assertIn("+  listen 443 ssl;", plan_resp["data"]["diff"])
        token = plan_resp["data"]["plan_token"]

        # 3. Approve and apply restores real secret in memory before writing remote
        engine.handle_admin_request("admin.approve", {"plan_token": token, "actor": "human:bob"})
        applied = engine.handle_client_request("config.apply", {"plan_token": token})
        self.assertTrue(applied["ok"])
        self.assertTrue(applied["data"]["reloaded"])
        self.assertFalse(applied["data"]["rolled_back"])
        self.assertEqual(applied["data"]["backup_id"], "nginx-site.20261124.bak")
        self.assertIn("api_secret=topsecret_42", self.remote_config_content)
        self.assertIn("listen 443 ssl;", self.remote_config_content)

        # 4. Rollback two-phase
        rb_plan = engine.handle_client_request(
            "config.rollback_plan",
            {
                "server": "prod-web",
                "config_id": "nginx-site",
                "backup_id": "nginx-site.20261124.bak",
                "reason": "Revert TLS test",
            },
        )
        self.assertTrue(rb_plan["ok"])
        rb_tok = rb_plan["data"]["plan_token"]
        engine.handle_admin_request("admin.approve", {"plan_token": rb_tok, "actor": "human:bob"})
        rb_applied = engine.handle_client_request("config.rollback_apply", {"plan_token": rb_tok})
        self.assertTrue(rb_applied["ok"])
        self.assertEqual(rb_applied["data"]["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()

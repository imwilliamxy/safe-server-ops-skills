"""Tests for the two-phase approval state machine and anti-self-approval isolation."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from safe_server_ops.audit import AuditLogger
from safe_server_ops.config import load_policy, load_server_profiles
from safe_server_ops.daemon import OpsEngine
from safe_server_ops.planner import PlanError, PlanStore


class PlannerAndIsolationTests(unittest.TestCase):
    def test_plan_lifecycle_and_replay_protection(self) -> None:
        store = PlanStore(ttl_seconds=60)
        plan = store.create(
            kind="docker_restart",
            server="prod-web",
            target="web-app",
            reason="OOM recovery",
            summary="Restart web-app",
            payload={"server": "prod-web", "target": "web-app"},
        )

        # Cannot consume before approval
        with self.assertRaises(PlanError):
            store.consume_approved(plan.token, expected_kind="docker_restart")

        # Approve via admin path
        approved = store.approve(plan.token, approved_by="human:alice")
        self.assertEqual(approved["status"], "APPROVED")

        # Kind mismatch fails
        with self.assertRaises(PlanError):
            store.consume_approved(plan.token, expected_kind="rsync_sync")

        # Valid consumption succeeds once
        consumed = store.consume_approved(plan.token, expected_kind="docker_restart")
        self.assertEqual(consumed.approved_by, "human:alice")

        # Replay fails
        with self.assertRaises(PlanError):
            store.consume_approved(plan.token, expected_kind="docker_restart")

    def test_plan_expiration(self) -> None:
        store = PlanStore(ttl_seconds=1)
        plan = store.create(
            kind="rsync_sync",
            server="prod-web",
            target="release",
            reason="deploy",
            summary="sync",
            payload={},
        )
        plan.expires_at = time.time() - 1
        with self.assertRaises(PlanError):
            store.approve(plan.token, approved_by="human:alice")

    def test_client_socket_forbids_admin_methods(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "id_ops"
            key.write_text("dummy", encoding="utf-8")
            env = root / ".ssh-servers.env"
            env.write_text(
                f"[prod-web]\nHOST=198.51.100.10\nUSER=ai-ops\nPORT=22\nKEY_FILE={key}\n",
                encoding="utf-8",
            )
            pol = root / "policy.yaml"
            pol.write_text("servers:\n  prod-web: {}\n", encoding="utf-8")

            engine = OpsEngine(
                profiles=load_server_profiles(env),
                policy=load_policy(pol, known_servers={"prod-web"}),
                audit=AuditLogger(root / "audit.jsonl"),
            )

            # AI attempting to self-approve on client handler must be denied
            resp = engine.handle_client_request("admin.approve", {"plan_token": "pln_123"})
            self.assertFalse(resp["ok"])
            self.assertIn("forbidden", resp["error"].lower())

            resp_list = engine.handle_client_request("admin.list_pending", {})
            self.assertFalse(resp_list["ok"])


if __name__ == "__main__":
    unittest.main()

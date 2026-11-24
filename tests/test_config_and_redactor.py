"""Tests for literal config parsing, policy validation, and output/config redaction."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from safe_server_ops.config import ConfigError, load_policy, load_server_profiles
from safe_server_ops.redactor import (
    Redactor,
    SecretPlaceholderError,
    mask_config_secrets,
    truncate_output,
    unmask_config_secrets,
)


class ConfigAndRedactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.key_ops = self.root / "id_ops"
        self.key_sync = self.root / "id_sync"
        self.key_ops.write_text("dummy-ops-key", encoding="utf-8")
        self.key_sync.write_text("dummy-sync-key", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_load_server_profiles_literal_and_sync_key(self) -> None:
        env_file = self.root / ".ssh-servers.env"
        env_file.write_text(
            f"""
            # literal config
            [prod-web]
            HOST='198.51.100.42'
            USER="deploy_ai"
            PORT=2222
            KEY_FILE={self.key_ops}
            SYNC_KEY_FILE={self.key_sync}
            """,
            encoding="utf-8",
        )
        profiles = load_server_profiles(env_file)
        self.assertIn("prod-web", profiles)
        p = profiles["prod-web"]
        self.assertEqual(p.host, "198.51.100.42")
        self.assertEqual(p.user, "deploy_ai")
        self.assertEqual(p.port, 2222)
        self.assertEqual(p.key_file, self.key_ops)
        self.assertEqual(p.effective_sync_key(), self.key_sync)

    def test_reject_symlink_env_file(self) -> None:
        real_env = self.root / "real.env"
        real_env.write_text(
            f"[a]\nHOST=198.51.100.1\nUSER=ai\nPORT=22\nKEY_FILE={self.key_ops}\n",
            encoding="utf-8",
        )
        link_env = self.root / "link.env"
        os.symlink(real_env, link_env)
        with self.assertRaises(ConfigError):
            load_server_profiles(link_env)

    def test_reject_insecure_policy_options(self) -> None:
        pol = self.root / "bad_policy.yaml"
        pol.write_text(
            """
global:
  strict_host_key_checking: "no"
servers: {}
""",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError):
            load_policy(pol)

        pol2 = self.root / "traversal_policy.yaml"
        pol2.write_text(
            """
servers:
  prod-web:
    logs:
      bad:
        type: file
        path: /var/log/../../etc/shadow
""",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError):
            load_policy(pol2, known_servers={"prod-web"})

    def test_redactor_scrubs_all_sensitive_artifacts(self) -> None:
        env_file = self.root / ".ssh-servers.env"
        env_file.write_text(
            f"[prod-web]\nHOST=198.51.100.42\nUSER=deploy_ai\nPORT=22\nKEY_FILE={self.key_ops}\n",
            encoding="utf-8",
        )
        profiles = load_server_profiles(env_file)
        redactor = Redactor(profiles)

        dirty = (
            f"ssh: connect to host 198.51.100.42 port 22: Permission denied for deploy_ai@198.51.100.42\n"
            f"Using key {self.key_ops} with -e 'ssh -i {self.key_ops} -p 22'\n"
            "Extra IP 10.20.30.40 and mysql://dbuser:SuperPass123@10.0.0.5/app\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload\n"
            "AWS=AKIAIOSFODNN7EXAMPLE\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETBODY\n-----END OPENSSH PRIVATE KEY-----\n"
            "Remote root /var/www/secret-site"
        )
        clean = redactor.redact(
            dirty,
            active_profile=profiles["prod-web"],
            extra_literals=[("/var/www/secret-site", "[TARGET_REMOTE_ROOT]")],
        )

        for secret in (
            "198.51.100.42",
            "deploy_ai",
            str(self.key_ops),
            "10.20.30.40",
            "SuperPass123",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "AKIAIOSFODNN7EXAMPLE",
            "SECRETBODY",
            "/var/www/secret-site",
        ):
            self.assertNotIn(secret, clean)
        self.assertIn("[REDACTED_PRIVATE_KEY]", clean)
        self.assertIn("[TARGET_REMOTE_ROOT]", clean)

    def test_config_secret_mask_and_unmask_integrity(self) -> None:
        raw = "server_name example.com;\nproxy_set_header X-Api-Key api_key=my_ultra_secret_99;\nlisten 80;\n"
        patterns = [r"(?i)(password|secret|token|api_key)\s*[:=]\s*[^\s;]+"]
        masked, smap = mask_config_secrets(raw, patterns)
        self.assertNotIn("my_ultra_secret_99", masked)
        self.assertIn("{{REDACTED_SECRET_1}}", masked)

        # Valid edit keeping placeholder intact
        draft = masked.replace("listen 80;", "listen 443;")
        restored = unmask_config_secrets(draft, smap)
        self.assertIn("api_key=my_ultra_secret_99", restored)
        self.assertIn("listen 443;", restored)

        # Tampering: deleting secret placeholder must fail
        with self.assertRaises(SecretPlaceholderError):
            unmask_config_secrets(masked.replace("{{REDACTED_SECRET_1}}", "hacked"), smap)

        # Tampering: inventing unknown placeholder must fail
        with self.assertRaises(SecretPlaceholderError):
            unmask_config_secrets(masked + "\n# {{REDACTED_SECRET_99}}\n", smap)

    def test_truncate_output(self) -> None:
        text = "a" * 5000
        out = truncate_output(text, 1024)
        self.assertLessEqual(len(out.encode("utf-8")), 1024)
        self.assertIn("[OUTPUT TRUNCATED]", out)


if __name__ == "__main__":
    unittest.main()

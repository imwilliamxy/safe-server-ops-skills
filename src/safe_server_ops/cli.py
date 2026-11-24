"""opsctl: Zero-credential thin CLI client for AI agents and operators."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .protocol import ProtocolError, resolve_socket_path, send_request


def _print_result(resp: dict[str, Any], as_json: bool) -> int:
    if as_json:
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return 0 if resp.get("ok") else 1

    if not resp.get("ok"):
        print(f"ERROR: {resp.get('error', 'Unknown error')}", file=sys.stderr)
        return 1

    data = resp.get("data", {})
    if isinstance(data, dict) and "content" in data and "log_id" in data:
        print(
            f"# logs {data['server']}:{data['log_id']} (lines={data['lines_requested']}, exit_code={data['exit_code']})"
        )
        if data.get("content"):
            print(data["content"])
        if data.get("stderr"):
            print("--- stderr ---", file=sys.stderr)
            print(data["stderr"], file=sys.stderr)
        return 0 if data.get("exit_code") == 0 else 1

    if isinstance(data, dict) and "plan_token" in data and data.get("status") == "PENDING_APPROVAL":
        print(f"PLAN CREATED (status: {data['status']}, expires in {data['expires_in_seconds']}s)")
        print(f"  plan_token : {data['plan_token']}")
        print(f"  kind       : {data['kind']}")
        print(f"  server     : {data['server']}")
        print(f"  target     : {data['target']}")
        print(f"  summary    : {data['summary']}")
        if data.get("diff"):
            print("\n--- diff / changes ---")
            print(data["diff"])
        print(
            f"\nNext step (human approval required):\n"
            f"  sudo -u sshops ops-approve --show {data['plan_token']}\n"
            f"  sudo -u sshops ops-approve approve {data['plan_token']}"
        )
        return 0

    print(json.dumps(data, ensure_ascii=False, indent=2))
    exit_code = data.get("exit_code") if isinstance(data, dict) else None
    return 0 if exit_code in (None, 0) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opsctl",
        description="Credential-less CLI client for safe-server-ops (opsd).",
    )
    parser.add_argument("--socket", default=None, help="Path to opsd client Unix socket (or OPS_SOCKET)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output raw JSON response")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("capabilities", help="List allowed server aliases, logs, Docker targets, configs, and sync targets")

    p_logs = sub.add_parser("logs", help="Read whitelisted server or Docker logs (L0)")
    p_logs.add_argument("server", help="Server logical alias")
    p_logs.add_argument("log_id", help="Whitelisted log source ID")
    p_logs.add_argument("--lines", type=int, default=100, help="Number of tail lines")
    p_logs.add_argument("--keyword", default=None, help="Fixed literal substring filter")

    p_docker = sub.add_parser("docker", help="Inspect or restart whitelisted Docker targets")
    dsub = p_docker.add_subparsers(dest="docker_cmd", required=True)

    p_dstatus = dsub.add_parser("status", help="Show whitelisted Docker status (L0)")
    p_dstatus.add_argument("server", help="Server logical alias")
    p_dstatus.add_argument("target", nargs="?", default=None, help="Optional container or stack:service")

    p_drplan = dsub.add_parser("restart-plan", help="Create a Docker restart plan (L0 -> requires approval)")
    p_drplan.add_argument("server", help="Server logical alias")
    p_drplan.add_argument("target", help="Whitelisted container or stack:service")
    p_drplan.add_argument("--reason", required=True, help="Reason for restarting")

    p_drapply = dsub.add_parser("restart-apply", help="Apply an approved Docker restart plan (L1)")
    p_drapply.add_argument("plan_token", help="Approved plan token")

    p_rsync = sub.add_parser("rsync", help="Two-phase safe rsync file synchronization")
    rsub = p_rsync.add_subparsers(dest="rsync_cmd", required=True)

    p_rprev = rsub.add_parser("preview", help="Dry-run preview & manifest hash (L0 -> requires approval)")
    p_rprev.add_argument("target", help="Whitelisted sync_target ID")

    p_rapply = rsub.add_parser("apply", help="Apply an approved rsync plan (L2)")
    p_rapply.add_argument("plan_token", help="Approved plan token")

    p_cfg = sub.add_parser("config", help="Read, validate, apply, and rollback whitelisted configs")
    csub = p_cfg.add_subparsers(dest="config_cmd", required=True)

    p_cread = csub.add_parser("read", help="Read config with secrets masked (L0)")
    p_cread.add_argument("server", help="Server logical alias")
    p_cread.add_argument("config_id", help="Whitelisted config ID")

    p_cplan = csub.add_parser("plan", help="Validate draft config and generate diff plan (L0 -> requires approval)")
    p_cplan.add_argument("server", help="Server logical alias")
    p_cplan.add_argument("config_id", help="Whitelisted config ID")
    p_cplan.add_argument("--file", required=True, help="Local draft file path")
    p_cplan.add_argument("--base-sha", required=True, help="base_sha256 returned by config read")
    p_cplan.add_argument("--reason", required=True, help="Reason for config modification")

    p_capply = csub.add_parser("apply", help="Apply an approved config change plan (L2)")
    p_capply.add_argument("plan_token", help="Approved plan token")

    p_cbak = csub.add_parser("backups", help="List available backups for a config (L0)")
    p_cbak.add_argument("server", help="Server logical alias")
    p_cbak.add_argument("config_id", help="Whitelisted config ID")

    p_crb_plan = csub.add_parser("rollback-plan", help="Create a config rollback plan (L0 -> requires approval)")
    p_crb_plan.add_argument("server", help="Server logical alias")
    p_crb_plan.add_argument("config_id", help="Whitelisted config ID")
    p_crb_plan.add_argument("backup_id", help="Backup ID from config backups")
    p_crb_plan.add_argument("--reason", required=True, help="Reason for rollback")

    p_crb_apply = csub.add_parser("rollback-apply", help="Apply an approved config rollback plan (L1)")
    p_crb_apply.add_argument("plan_token", help="Approved plan token")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    sock = resolve_socket_path(args.socket)

    method = ""
    params: dict[str, Any] = {}

    if args.cmd == "capabilities":
        method = "capabilities"
    elif args.cmd == "logs":
        method = "logs"
        params = {
            "server": args.server,
            "log_id": args.log_id,
            "lines": args.lines,
            "keyword": args.keyword,
        }
    elif args.cmd == "docker":
        if args.docker_cmd == "status":
            method = "docker.status"
            params = {"server": args.server, "target": args.target}
        elif args.docker_cmd == "restart-plan":
            method = "docker.restart_plan"
            params = {"server": args.server, "target": args.target, "reason": args.reason}
        elif args.docker_cmd == "restart-apply":
            method = "docker.restart_apply"
            params = {"plan_token": args.plan_token}
    elif args.cmd == "rsync":
        if args.rsync_cmd == "preview":
            method = "rsync.preview"
            params = {"target": args.target}
        elif args.rsync_cmd == "apply":
            method = "rsync.apply"
            params = {"plan_token": args.plan_token}
    elif args.cmd == "config":
        if args.config_cmd == "read":
            method = "config.read"
            params = {"server": args.server, "config_id": args.config_id}
        elif args.config_cmd == "plan":
            draft_path = Path(args.file)
            if not draft_path.is_file():
                print(f"ERROR: Draft file not found: {draft_path}", file=sys.stderr)
                return 1
            method = "config.plan"
            params = {
                "server": args.server,
                "config_id": args.config_id,
                "draft_content": draft_path.read_text(encoding="utf-8"),
                "base_sha256": args.base_sha,
                "reason": args.reason,
            }
        elif args.config_cmd == "apply":
            method = "config.apply"
            params = {"plan_token": args.plan_token}
        elif args.config_cmd == "backups":
            method = "config.backups"
            params = {"server": args.server, "config_id": args.config_id}
        elif args.config_cmd == "rollback-plan":
            method = "config.rollback_plan"
            params = {
                "server": args.server,
                "config_id": args.config_id,
                "backup_id": args.backup_id,
                "reason": args.reason,
            }
        elif args.config_cmd == "rollback-apply":
            method = "config.rollback_apply"
            params = {"plan_token": args.plan_token}

    try:
        resp = send_request(sock, method, params)
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return _print_result(resp, as_json=args.as_json)


if __name__ == "__main__":
    raise SystemExit(main())

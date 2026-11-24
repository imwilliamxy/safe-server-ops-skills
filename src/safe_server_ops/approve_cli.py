"""ops-approve: Human-only approval CLI communicating over admin.sock (0600)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from .protocol import ProtocolError, resolve_admin_socket_path, send_request


def _detect_actor() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    current = getpass.getuser()
    if sudo_user:
        return f"human:{sudo_user} (via sudo->{current})"
    return f"human:{current}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ops-approve",
        description="Human-only approval tool for opsd (connects to 0600 admin.sock).",
    )
    parser.add_argument(
        "--admin-socket",
        default=None,
        help="Path to opsd admin Unix socket (or OPS_ADMIN_SOCKET)",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output raw JSON")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", dest="list_pending", help="List pending plans")
    group.add_argument("--show", metavar="PLAN_TOKEN", help="Inspect full plan summary and diff")
    group.add_argument("--approve", metavar="PLAN_TOKEN", help="Approve a pending plan token")
    group.add_argument("--reject", metavar="PLAN_TOKEN", help="Reject a pending plan token")

    # Also support positional shorthand anywhere: `ops-approve [opts] approve <token>`
    if argv is None:
        argv = sys.argv[1:]
    normalized: list[str] = []
    skip_next = False
    for tok in argv:
        if skip_next:
            normalized.append(tok)
            skip_next = False
            continue
        if tok == "--admin-socket":
            normalized.append(tok)
            skip_next = True
            continue
        if tok in {"approve", "reject", "show"}:
            normalized.append(f"--{tok}")
        else:
            normalized.append(tok)

    args = parser.parse_args(normalized)
    sock = resolve_admin_socket_path(args.admin_socket)
    actor = _detect_actor()

    if args.list_pending:
        method, params = "admin.list_pending", {}
    elif args.show:
        method, params = "admin.show_plan", {"plan_token": args.show}
    elif args.approve:
        method, params = "admin.approve", {"plan_token": args.approve, "actor": actor}
    else:
        method, params = "admin.reject", {"plan_token": args.reject, "actor": actor}

    try:
        resp = send_request(sock, method, params)
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return 0 if resp.get("ok") else 1

    if not resp.get("ok"):
        print(f"ERROR: {resp.get('error', 'Unknown error')}", file=sys.stderr)
        return 1

    data = resp["data"]
    if args.list_pending:
        pending = data.get("pending", [])
        if not pending:
            print("No pending approval plans.")
            return 0
        for p in pending:
            print(
                f"{p['plan_token']}  [{p['kind']}]  {p['server']}/{p['target']}  "
                f"(expires in {p['expires_in_seconds']}s)\n"
                f"  reason : {p['reason']}\n"
                f"  summary: {p['summary']}"
            )
        return 0

    if args.show:
        print(f"plan_token : {data['plan_token']}")
        print(f"status     : {data['status']} (expires in {data['expires_in_seconds']}s)")
        print(f"kind       : {data['kind']}")
        print(f"server     : {data['server']}")
        print(f"target     : {data['target']}")
        print(f"reason     : {data['reason']}")
        print(f"summary    : {data['summary']}")
        if data.get("diff"):
            print("\n--- diff / changes ---")
            print(data["diff"])
        return 0

    print(f"{data['plan_token']} -> {data['status']} ({data.get('approved_by', actor)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

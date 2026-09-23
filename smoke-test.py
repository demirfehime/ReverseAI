#!/usr/bin/env python3
"""Dependency-free smoke test for the local ReverseAI metadata API."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SESSION_TOKEN = ""


def request(base: str, path: str, method: str = "GET", payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if SESSION_TOKEN:
        headers["X-ReverseAI-Token"] = SESSION_TOKEN
    request_obj = urllib.request.Request(f"{base.rstrip('/')}{path}", data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request_obj, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接 {base}: {exc.reason}") from exc


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"检查失败: {message}")
    print(f"[ok] {message}")


def main() -> int:
    global SESSION_TOKEN
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="测试现有服务（必须同时指定 --keep-state，测试记录会保留）")
    parser.add_argument("--keep-state", action="store_true", help="明确允许向 --base 服务写入并保留测试记录")
    args = parser.parse_args()
    if args.base and not args.keep_state:
        parser.error("测试现有服务需要 --keep-state；不指定 --base 可使用自动隔离测试")
    if args.keep_state and not args.base:
        parser.error("--keep-state 仅与 --base 一起使用")
    server = thread = temporary = None
    try:
        if not args.base:
            from server import create_server
            temporary = tempfile.TemporaryDirectory(prefix="reverseai-smoke-")
            server = create_server(port=0, data_path=Path(temporary.name) / "state.json")
            server.quiet = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            args.base = f"http://127.0.0.1:{server.server_address[1]}"
        health = request(args.base, "/api/health")
        SESSION_TOKEN = health.get("csrf_token", "")
        check(health.get("ok") is True and bool(SESSION_TOKEN), "health endpoint and session token")
        cases = request(args.base, "/api/cases")
        check(bool(cases.get("items")), "cases endpoint")
        case_id = cases["items"][0]["id"]
        samples = request(args.base, "/api/samples")
        check(isinstance(samples.get("items"), list), "samples GET endpoint")
        sample = request(args.base, "/api/samples", "POST", {
            "case_id": case_id, "name": "smoke-test-metadata.exe", "size": 0,
            "mime": "application/octet-stream", "sha256": "a" * 64, "kind": "PE 64-bit",
        })
        check(sample.get("sample", {}).get("name") == "smoke-test-metadata.exe", "sample metadata POST")
        sample_id = sample["sample"]["id"]
        job = request(args.base, "/api/analysis/jobs", "POST", {
            "case_id": case_id, "sample_id": sample_id, "type": "metadata_check",
        })
        check(job.get("status") == "completed", "metadata check job POST")
        evidence = request(args.base, f"/api/evidence/{case_id}")
        check(isinstance(evidence.get("items"), list), "evidence endpoint")
        toolchain = request(args.base, "/api/toolchain/health")
        check(isinstance(toolchain.get("items"), dict), "toolchain health endpoint")
        answer = request(args.base, "/api/copilot/messages", "POST", {
            "case_id": case_id, "sample_id": sample_id, "message": "请解释当前证据链",
        })
        check(bool(answer.get("message", {}).get("content")), "copilot message POST")
        report = request(args.base, "/api/reports", "POST", {"case_id": case_id, "format": "json"})
        check(report.get("status") == "completed", "report POST")
        downloaded = request(args.base, f"/api/reports/{report['id']}/download")
        check(downloaded.get("snapshot", {}).get("case", {}).get("id") == case_id, "report download")
        print("Smoke test passed: metadata-only API flow is healthy.")
        return 0
    except (RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"Smoke test failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        if temporary is not None:
            temporary.cleanup()
            print("[ok] isolated test data removed; workspace state untouched")


if __name__ == "__main__":
    raise SystemExit(main())

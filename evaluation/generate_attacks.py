import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import httpx


NORMAL_ENDPOINTS = ["/", "/login", "/status", "/api/v1/login"]
SCAN_ENDPOINTS = ["/admin", "/debug", "/api/v1/users", "/api/v1/admin", "/.env", "/server-status"]
USER_AGENTS = [
    "Mozilla/5.0 Chrome/124.0",
    "Mozilla/5.0 Firefox/126.0",
    "curl/8.1.2",
    "python-httpx/0.27",
]
SQL_PAYLOADS = ["' OR 1=1--", "admin' UNION SELECT 1,2--", "'; DROP TABLE users; --"]


def make_event(
    ip_address: str,
    service_type: str = "http",
    request_type: str = "GET",
    endpoint: str = "/",
    username: str | None = None,
    password: str | None = None,
    payload: str | None = None,
    label: str = "normal",
) -> dict:
    return {
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service_type": service_type,
        "request_type": request_type,
        "endpoint": endpoint,
        "username": username,
        "password": password,
        "payload": payload,
        "user_agent": random.choice(USER_AGENTS),
        "expected_attack_type": None if label == "normal" else label,
        "expected_is_attack": label != "normal",
    }


def normal_browsing(count: int) -> list[dict]:
    return [
        make_event(
            ip_address=f"10.0.0.{random.randint(1, 250)}",
            endpoint=random.choice(NORMAL_ENDPOINTS),
            request_type=random.choice(["GET", "GET", "POST"]),
            label="normal",
        )
        for _ in range(count)
    ]


def brute_force(count: int) -> list[dict]:
    ip = "203.0.113.10"
    return [
        make_event(
            ip_address=ip,
            request_type="POST",
            endpoint="/login",
            username=f"admin{i % 5}",
            password=f"guess-{i}",
            label="brute_force",
        )
        for i in range(count)
    ]


def port_scan(count: int) -> list[dict]:
    ip = "203.0.113.20"
    return [
        make_event(
            ip_address=ip,
            endpoint=SCAN_ENDPOINTS[i % len(SCAN_ENDPOINTS)],
            request_type="GET",
            label="port_scanning",
        )
        for i in range(count)
    ]


def credential_stuffing(count: int) -> list[dict]:
    users = ["admin", "root", "test", "support", "backup"]
    return [
        make_event(
            ip_address=f"198.51.100.{(i % 20) + 1}",
            request_type="POST",
            endpoint="/login",
            username=users[i % len(users)],
            password=f"Password{i % 9}!",
            label="credential_stuffing",
        )
        for i in range(count)
    ]


def injection(count: int) -> list[dict]:
    return [
        make_event(
            ip_address="203.0.113.30",
            request_type="POST",
            endpoint="/api/v1/login",
            username="admin",
            password=random.choice(SQL_PAYLOADS),
            payload=random.choice(SQL_PAYLOADS),
            label="injection",
        )
        for _ in range(count)
    ]


def mixed(count: int) -> list[dict]:
    chunks = [
        normal_browsing(int(count * 0.6)),
        brute_force(max(1, int(count * 0.15))),
        port_scan(max(1, int(count * 0.1))),
        credential_stuffing(max(1, int(count * 0.1))),
        injection(max(1, count - int(count * 0.95))),
    ]
    events = [event for chunk in chunks for event in chunk]
    random.shuffle(events)
    return events[:count]


SCENARIOS = {
    "normal": normal_browsing,
    "brute_force": brute_force,
    "port_scan": port_scan,
    "credential_stuffing": credential_stuffing,
    "injection": injection,
    "mixed": mixed,
}


def write_events(events: Iterable[dict], output: str) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    events = list(events)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
    else:
        with path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")


def send_events(events: Iterable[dict], target_url: str) -> None:
    with httpx.Client(timeout=5.0) as client:
        for event in events:
            client.post(target_url.rstrip("/") + event["endpoint"], json=event)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate safe synthetic honeypot evaluation traffic.")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="mixed")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--target-url")
    parser.add_argument("--output", default="evaluation/generated_events.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    events = SCENARIOS[args.scenario](args.count)
    if args.target_url:
        send_events(events, args.target_url)
    write_events(events, args.output)
    print(f"Wrote {len(events)} {args.scenario} events to {args.output}")


if __name__ == "__main__":
    main()

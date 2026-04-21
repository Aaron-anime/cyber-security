from __future__ import annotations

import json
import hashlib
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_lab.db"
app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")

ALLOWED_PROFILES = {"quick", "standard", "deep"}
MAX_PORTS = 10


def init_db() -> None:
    """Create SQLite tables used for persistent security logs."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_utc TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                profile TEXT NOT NULL,
                ports_json TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                finding_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_feed_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fetched_at_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                indicator_count INTEGER NOT NULL,
                indicators_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def insert_scan_history(entry: dict[str, Any]) -> None:
    """Persist a completed scan result to SQLite."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scan_history (
                created_at_utc,
                scan_id,
                target,
                target_type,
                profile,
                ports_json,
                findings_json,
                finding_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["timestamp_utc"],
                entry["scan_id"],
                entry["target"],
                entry["target_type"],
                entry["profile"],
                json.dumps(entry["ports"]),
                json.dumps(entry["findings"]),
                entry["finding_count"],
            ),
        )
        conn.commit()


def insert_threat_feed_audit(feed: dict[str, Any]) -> None:
    """Persist threat feed fetch events for auditing."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO threat_feed_audit (
                fetched_at_utc,
                source,
                indicator_count,
                indicators_json
            ) VALUES (?, ?, ?, ?)
            """,
            (
                feed["fetched_at_utc"],
                feed["source"],
                len(feed["indicators"]),
                json.dumps(feed["indicators"]),
            ),
        )
        conn.commit()


def fetch_recent_scan_history(limit: int = 20) -> list[dict[str, Any]]:
    """Read recent scan history entries for frontend/API use."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                id,
                created_at_utc,
                scan_id,
                target,
                target_type,
                profile,
                ports_json,
                findings_json,
                finding_count
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    history: list[dict[str, Any]] = []
    for row in rows:
        history.append(
            {
                "id": row["id"],
                "created_at_utc": row["created_at_utc"],
                "scan_id": row["scan_id"],
                "target": row["target"],
                "target_type": row["target_type"],
                "profile": row["profile"],
                "ports": json.loads(row["ports_json"]),
                "findings": json.loads(row["findings_json"]),
                "finding_count": row["finding_count"],
            }
        )
    return history


def fetch_recent_threat_feed_audit(limit: int = 20) -> list[dict[str, Any]]:
    """Read recent threat feed fetch audits for frontend/API use."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                id,
                fetched_at_utc,
                source,
                indicator_count,
                indicators_json
            FROM threat_feed_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    audits: list[dict[str, Any]] = []
    for row in rows:
        audits.append(
            {
                "id": row["id"],
                "fetched_at_utc": row["fetched_at_utc"],
                "source": row["source"],
                "indicator_count": row["indicator_count"],
                "indicators": json.loads(row["indicators_json"]),
            }
        )
    return audits


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_safe_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False

    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    return True


def normalize_ports(raw: Any) -> list[int] | None:
    if not isinstance(raw, list):
        return None

    cleaned: list[int] = []
    for item in raw:
        if not isinstance(item, int):
            return None
        if item < 1 or item > 65535:
            return None
        cleaned.append(item)

    unique_ports = sorted(set(cleaned))
    return unique_ports[:MAX_PORTS]


def build_scan_findings(profile: str, ports: list[int]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = [
        {
            "id": "SIM-001",
            "severity": "medium",
            "title": "Missing Security Headers",
            "recommendation": "Enable HSTS, X-Frame-Options, and CSP headers.",
        },
        {
            "id": "SIM-002",
            "severity": "low",
            "title": "Verbose Server Banner",
            "recommendation": "Reduce server version disclosure in response headers.",
        },
    ]

    if profile in {"standard", "deep"}:
        findings.append(
            {
                "id": "SIM-003",
                "severity": "high",
                "title": "Weak TLS Cipher Preference",
                "recommendation": "Disable deprecated ciphers and enforce modern suites.",
            }
        )

    if profile == "deep":
        findings.append(
            {
                "id": "SIM-005",
                "severity": "medium",
                "title": "Potential Directory Listing",
                "recommendation": "Disable directory indexing on web server paths.",
            }
        )

    if 8080 in ports or 8443 in ports:
        findings.append(
            {
                "id": "SIM-004",
                "severity": "medium",
                "title": "Administrative Port Exposure",
                "recommendation": "Restrict administrative interfaces to trusted ranges.",
            }
        )

    return findings


@app.after_request
def add_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.get("/")
def index() -> Response:
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/scanner")
def scanner_page() -> Response:
    return send_from_directory(BASE_DIR, "scanner.html")


@app.get("/login")
def login_page() -> Response:
    return send_from_directory(BASE_DIR, "login.html")


@app.get("/api/threat-feed")
def threat_feed() -> Response:
    feed = {
        "fetched_at_utc": utc_now_iso(),
        "source": "server-mock-feed",
        "indicators": [
            {
                "type": "ip",
                "value": "185.199.108.153",
                "severity": "high",
                "label": "Known C2 infrastructure",
            },
            {
                "type": "domain",
                "value": "update-check-secure.net",
                "severity": "medium",
                "label": "Suspicious updater domain",
            },
            {
                "type": "hash_sha256",
                "value": "8b8c740bb7f4f4f9187a5ee4b6fce1a3a6764b64f2fcae5abf2527be13d7f3e7",
                "severity": "high",
                "label": "Malware sample fingerprint",
            },
        ],
    }
    insert_threat_feed_audit(feed)
    return jsonify(feed)


@app.get("/api/history/scans")
def scan_history() -> Response:
    history = fetch_recent_scan_history(limit=20)
    return jsonify(
        {
            "fetched_at_utc": utc_now_iso(),
            "count": len(history),
            "items": history,
        }
    )


@app.get("/api/history/threat-feed")
def threat_feed_history() -> Response:
    audits = fetch_recent_threat_feed_audit(limit=20)
    return jsonify(
        {
            "fetched_at_utc": utc_now_iso(),
            "count": len(audits),
            "items": audits,
        }
    )


@app.post("/api/scan")
def scan_target() -> Response:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body."}), 400

    target = payload.get("target")
    profile = payload.get("profile", "standard")
    ports_raw = payload.get("ports", [80, 443])

    if not isinstance(target, str) or not is_safe_url(target):
        return jsonify({"error": "Invalid target URL. Use http or https."}), 400

    if not isinstance(profile, str) or profile not in ALLOWED_PROFILES:
        return jsonify({"error": "Invalid scan profile."}), 400

    ports = normalize_ports(ports_raw)
    if ports is None:
        return jsonify({"error": "Invalid ports list."}), 400

    fingerprint_seed = f"{target}|{profile}|{'-'.join(map(str, ports))}".encode("utf-8")
    scan_id = "SIM-" + hashlib.sha256(fingerprint_seed).hexdigest()[:16]

    parsed = urlparse(target)
    host = parsed.hostname or "unknown"
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    findings = build_scan_findings(profile, ports)
    result = {
        "simulation": True,
        "scan_id": scan_id,
        "timestamp_utc": utc_now_iso(),
        "target": target,
        "target_type": "ip" if is_ip else "domain",
        "profile": profile,
        "ports": ports,
        "findings": findings,
        "finding_count": len(findings),
    }
    insert_scan_history(result)
    return jsonify(result)


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

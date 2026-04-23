from __future__ import annotations

import json
import hashlib
import ipaddress
import os
import sqlite3
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SECURITY_DB_PATH", "")) if os.getenv("SECURITY_DB_PATH") else (
    Path("/tmp/security_lab.db") if os.getenv("VERCEL") else BASE_DIR / "security_lab.db"
)
app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    default_limits=["240 per hour"],
)

ALLOWED_PROFILES = {"quick", "standard", "deep"}
MAX_PORTS = 10
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
OTX_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uploaded_at_utc TEXT NOT NULL,
                source_name TEXT NOT NULL,
                process_tree_json TEXT NOT NULL,
                flagged_network_json TEXT NOT NULL,
                report_json TEXT NOT NULL,
                process_count INTEGER NOT NULL,
                flagged_connection_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS event_log_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_log_text TEXT NOT NULL,
                parsed_events_json TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                severity_counts_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_query_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_utc TEXT NOT NULL,
                source TEXT NOT NULL,
                domain TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                outcome TEXT NOT NULL,
                resolved_ip TEXT NOT NULL,
                sinkhole_ip TEXT NOT NULL,
                metadata_json TEXT NOT NULL
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


def fetch_dashboard_summary() -> dict[str, Any]:
    """Build a compact operational summary for the main dashboard."""
    with sqlite3.connect(DB_PATH) as conn:
        scan_count = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] or 0
        threat_audit_count = conn.execute("SELECT COUNT(*) FROM threat_feed_audit").fetchone()[0] or 0
        ioc_report_count = conn.execute("SELECT COUNT(*) FROM ioc_reports").fetchone()[0] or 0

    latest_scan = fetch_recent_scan_history(limit=1)
    latest_threat_audit = fetch_recent_threat_feed_audit(limit=1)
    latest_ioc_report = fetch_latest_ioc_report()

    return {
        "fetched_at_utc": utc_now_iso(),
        "counts": {
            "scan_history": int(scan_count),
            "threat_feed_audits": int(threat_audit_count),
            "ioc_reports": int(ioc_report_count),
        },
        "latest": {
            "scan": latest_scan[0] if latest_scan else None,
            "threat_feed_audit": latest_threat_audit[0] if latest_threat_audit else None,
            "ioc_report": latest_ioc_report,
        },
    }


def insert_ioc_report(entry: dict[str, Any]) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO ioc_reports (
                uploaded_at_utc,
                source_name,
                process_tree_json,
                flagged_network_json,
                report_json,
                process_count,
                flagged_connection_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["uploaded_at_utc"],
                entry["source_name"],
                json.dumps(entry["process_tree"]),
                json.dumps(entry["flagged_network_connections"]),
                json.dumps(entry["report"]),
                entry["process_count"],
                entry["flagged_connection_count"],
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def fetch_latest_ioc_report() -> dict[str, Any] | None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
                id,
                uploaded_at_utc,
                source_name,
                process_tree_json,
                flagged_network_json,
                report_json,
                process_count,
                flagged_connection_count
            FROM ioc_reports
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    if row is None:
        return None

    report_data = json.loads(row["report_json"])
    report_iocs = report_data.get("iocs") if isinstance(report_data, dict) else {}
    process_events = report_iocs.get("process_events") if isinstance(report_iocs, dict) else []
    network_events = report_iocs.get("network_events") if isinstance(report_iocs, dict) else []

    return {
        "id": row["id"],
        "uploaded_at_utc": row["uploaded_at_utc"],
        "source_name": row["source_name"],
        "process_tree": json.loads(row["process_tree_json"]),
        "flagged_network_connections": json.loads(row["flagged_network_json"]),
        "report": report_data,
        "process_events": [event for event in process_events if isinstance(event, dict)]
        if isinstance(process_events, list)
        else [],
        "network_events": [event for event in network_events if isinstance(event, dict)]
        if isinstance(network_events, list)
        else [],
        "process_count": row["process_count"],
        "flagged_connection_count": row["flagged_connection_count"],
    }


def insert_event_log_analysis(entry: dict[str, Any]) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO event_log_analyses (
                created_at_utc,
                source,
                raw_log_text,
                parsed_events_json,
                event_count,
                severity_counts_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry["created_at_utc"],
                entry["source"],
                entry["raw_log_text"],
                json.dumps(entry["parsed_events"]),
                entry["event_count"],
                json.dumps(entry["severity_counts"]),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def fetch_recent_event_log_analyses(limit: int = 20) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                id,
                created_at_utc,
                source,
                raw_log_text,
                parsed_events_json,
                event_count,
                severity_counts_json
            FROM event_log_analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "created_at_utc": row["created_at_utc"],
                "source": row["source"],
                "raw_log_text": row["raw_log_text"],
                "parsed_events": json.loads(row["parsed_events_json"]),
                "event_count": row["event_count"],
                "severity_counts": json.loads(row["severity_counts_json"]),
            }
        )

    return items


def insert_dns_query_events(entries: list[dict[str, Any]]) -> int:
    if not entries:
        return 0

    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            """
            INSERT INTO dns_query_events (
                created_at_utc,
                source,
                domain,
                source_ip,
                outcome,
                resolved_ip,
                sinkhole_ip,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    entry["created_at_utc"],
                    entry["source"],
                    entry["domain"],
                    entry["source_ip"],
                    entry["outcome"],
                    entry["resolved_ip"],
                    entry["sinkhole_ip"],
                    json.dumps(entry["metadata"]),
                )
                for entry in entries
            ],
        )
        conn.commit()

    return len(entries)


def fetch_recent_dns_query_events(limit: int = 50) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                id,
                created_at_utc,
                source,
                domain,
                source_ip,
                outcome,
                resolved_ip,
                sinkhole_ip,
                metadata_json
            FROM dns_query_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "created_at_utc": row["created_at_utc"],
                "source": row["source"],
                "domain": row["domain"],
                "source_ip": row["source_ip"],
                "outcome": row["outcome"],
                "resolved_ip": row["resolved_ip"],
                "sinkhole_ip": row["sinkhole_ip"],
                "metadata": json.loads(row["metadata_json"]),
            }
        )

    return items


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


def timing_safe_equal(left: str, right: str) -> bool:
    max_len = max(len(left), len(right))
    diff = len(left) ^ len(right)
    for i in range(max_len):
        left_code = ord(left[i]) if i < len(left) else 0
        right_code = ord(right[i]) if i < len(right) else 0
        diff |= left_code ^ right_code
    return diff == 0


def to_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def build_process_tree(process_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes: dict[int, dict[str, Any]] = {}
    roots: list[dict[str, Any]] = []

    for event in process_events:
        pid = to_int(event.get("pid"), -1)
        ppid = to_int(event.get("ppid"), -1)
        if pid <= 0:
            continue
        nodes[pid] = {
            "pid": pid,
            "ppid": ppid,
            "name": str(event.get("name") or "unknown"),
            "cmdline": event.get("cmdline") if isinstance(event.get("cmdline"), list) else [],
            "timestamp_utc": str(event.get("timestamp_utc") or ""),
            "children": [],
        }

    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        if parent is None:
            roots.append(node)
        else:
            parent["children"].append(node)

    roots.sort(key=lambda item: (item["timestamp_utc"], item["pid"]))
    return roots


def extract_flagged_network_connections(network_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flagged: list[dict[str, Any]] = []
    for event in network_events:
        remote_ip = str(event.get("remote_ip") or "")
        remote_port = to_int(event.get("remote_port"), 0)
        is_dns_related = bool(event.get("is_dns_related"))

        try:
            parsed_ip = ipaddress.ip_address(remote_ip)
            is_public = not (
                parsed_ip.is_private
                or parsed_ip.is_loopback
                or parsed_ip.is_link_local
                or parsed_ip.is_multicast
                or parsed_ip.is_reserved
                or parsed_ip.is_unspecified
            )
        except ValueError:
            is_public = False

        suspicious_port = remote_port in {21, 22, 23, 25, 4444, 5555, 8080, 1337}
        if not (is_public or suspicious_port or is_dns_related):
            continue

        reason_parts: list[str] = []
        if is_public:
            reason_parts.append("public_ip")
        if suspicious_port:
            reason_parts.append("suspicious_port")
        if is_dns_related:
            reason_parts.append("dns_related")

        flagged.append(
            {
                "timestamp_utc": str(event.get("timestamp_utc") or ""),
                "pid": to_int(event.get("pid"), 0),
                "process_name": str(event.get("process_name") or "unknown"),
                "protocol": str(event.get("protocol") or ""),
                "local_ip": str(event.get("local_ip") or ""),
                "local_port": to_int(event.get("local_port"), 0),
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": str(event.get("status") or ""),
                "reason": ",".join(reason_parts),
            }
        )

    return flagged


def parse_ioc_report(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    iocs = report.get("iocs") if isinstance(report.get("iocs"), dict) else {}

    process_events = iocs.get("process_events") if isinstance(iocs.get("process_events"), list) else []
    network_events = iocs.get("network_events") if isinstance(iocs.get("network_events"), list) else []

    safe_process_events = [event for event in process_events if isinstance(event, dict)]
    safe_network_events = [event for event in network_events if isinstance(event, dict)]

    process_tree = build_process_tree(safe_process_events)
    flagged_connections = extract_flagged_network_connections(safe_network_events)
    return process_tree, flagged_connections


def fetch_otx_indicators() -> list[dict[str, str]]:
    headers = {"Accept": "application/json", "User-Agent": "cyber-shield-lab/1.0"}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    response = requests.get(
        OTX_EXPORT_URL,
        params={"type": "IPv4", "limit": 20},
        headers=headers,
        timeout=8,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, list):
        raise ValueError("Unexpected OTX response format")

    indicators: list[dict[str, str]] = []
    for item in data[:20]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("indicator") or item.get("ip") or "").strip()
        if not value:
            continue
        indicators.append(
            {
                "type": "ip",
                "value": value,
                "severity": "high" if str(item.get("reputation", "")).startswith("-") else "medium",
                "label": str(item.get("title") or "AlienVault OTX indicator"),
            }
        )
    return indicators


def fetch_feodo_indicators() -> list[dict[str, str]]:
    response = requests.get(
        FEODO_JSON_URL,
        headers={"Accept": "application/json", "User-Agent": "cyber-shield-lab/1.0"},
        timeout=8,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, list):
        raise ValueError("Unexpected Feodo response format")

    indicators: list[dict[str, str]] = []
    for item in data[:20]:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip_address") or "").strip()
        if not ip:
            continue
        malware = str(item.get("malware") or "unknown malware")
        status = str(item.get("status") or "")
        indicators.append(
            {
                "type": "ip",
                "value": ip,
                "severity": "high" if status.lower() == "online" else "medium",
                "label": f"abuse.ch Feodo ({malware})",
            }
        )
    return indicators


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
    source = "alienvault-otx"
    try:
        indicators = fetch_otx_indicators()
    except Exception:
        source = "abusech-feodo"
        indicators = fetch_feodo_indicators()

    feed = {
        "fetched_at_utc": utc_now_iso(),
        "source": source,
        "indicators": indicators,
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


@app.get("/api/history/event-logs")
def event_log_history() -> Response:
    items = fetch_recent_event_log_analyses(limit=20)
    return jsonify(
        {
            "fetched_at_utc": utc_now_iso(),
            "count": len(items),
            "items": items,
        }
    )


@app.get("/api/history/dns-simulator")
def dns_simulator_history() -> Response:
    items = fetch_recent_dns_query_events(limit=50)
    return jsonify(
        {
            "fetched_at_utc": utc_now_iso(),
            "count": len(items),
            "items": items,
        }
    )


@app.get("/api/dashboard/summary")
def dashboard_summary() -> Response:
    return jsonify(fetch_dashboard_summary())


@app.post("/api/scan")
@limiter.limit("20 per minute")
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


@app.post("/api/upload-report")
@app.post("/api/ioc-reports/upload")
@app.post("/api/ioc-reports/import")
@limiter.limit("8 per minute")
def upload_ioc_report() -> Response:
    source_name = "ioc_report.json"
    report_data: Any = None

    uploaded_file = request.files.get("report")
    if uploaded_file is not None:
        source_name = uploaded_file.filename or source_name
        try:
            report_data = json.load(uploaded_file.stream)
        except json.JSONDecodeError:
            return jsonify({"error": "Uploaded file is not valid JSON."}), 400
    else:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict) and isinstance(payload.get("report"), dict):
            report_data = payload["report"]
            source_name = str(payload.get("source_name") or source_name)
        elif isinstance(payload, dict):
            report_data = payload

    if not isinstance(report_data, dict):
        return jsonify({"error": "Provide IOC report JSON via multipart file or JSON body."}), 400

    process_tree, flagged_connections = parse_ioc_report(report_data)
    row_id = insert_ioc_report(
        {
            "uploaded_at_utc": utc_now_iso(),
            "source_name": source_name,
            "process_tree": process_tree,
            "flagged_network_connections": flagged_connections,
            "report": report_data,
            "process_count": len(report_data.get("iocs", {}).get("process_events", []))
            if isinstance(report_data.get("iocs"), dict)
            else 0,
            "flagged_connection_count": len(flagged_connections),
        }
    )

    return jsonify(
        {
            "status": "stored",
            "report_id": row_id,
            "uploaded_at_utc": utc_now_iso(),
            "source_name": source_name,
            "process_tree": process_tree,
            "flagged_network_connections": flagged_connections,
        }
    )


@app.post("/api/event-logs/analyze")
@limiter.limit("20 per minute")
def store_event_log_analysis() -> Response:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body."}), 400

    raw_logs = str(payload.get("raw_logs") or "")[:300000]
    source = str(payload.get("source") or "ui-event-log-analyzer")[:80]
    parsed_events = payload.get("parsed_events")

    if not isinstance(parsed_events, list):
        return jsonify({"error": "parsed_events must be an array."}), 400

    safe_events: list[dict[str, Any]] = [event for event in parsed_events if isinstance(event, dict)][:5000]
    severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARN": 0, "INFO": 0}

    for event in safe_events:
        severity = str(event.get("severity") or "").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    analysis_id = insert_event_log_analysis(
        {
            "created_at_utc": utc_now_iso(),
            "source": source,
            "raw_log_text": raw_logs,
            "parsed_events": safe_events,
            "event_count": len(safe_events),
            "severity_counts": severity_counts,
        }
    )

    return jsonify(
        {
            "status": "stored",
            "analysis_id": analysis_id,
            "created_at_utc": utc_now_iso(),
            "event_count": len(safe_events),
        }
    )


@app.post("/api/dns-simulator/events")
@limiter.limit("30 per minute")
def store_dns_simulator_events() -> Response:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body."}), 400

    events = payload.get("events")
    source = str(payload.get("source") or "ui-private-dns-simulator")[:80]
    sinkhole_ip = str(payload.get("sinkhole_ip") or "10.10.10.10")[:64]

    if not isinstance(events, list) or not events:
        return jsonify({"error": "events must be a non-empty array."}), 400

    safe_events: list[dict[str, Any]] = []
    for event in events[:1000]:
        if not isinstance(event, dict):
            continue

        domain = str(event.get("domain") or "").strip().lower()
        source_ip = str(event.get("sourceIp") or event.get("source_ip") or "").strip()
        outcome = str(event.get("outcome") or "ALLOW").strip().upper()
        resolved_ip = str(event.get("resolvedIp") or event.get("resolved_ip") or "").strip()
        timestamp = str(event.get("timestamp") or utc_now_iso())

        if not domain or not source_ip or not resolved_ip:
            continue

        safe_events.append(
            {
                "created_at_utc": timestamp,
                "source": source,
                "domain": domain,
                "source_ip": source_ip,
                "outcome": "SINKHOLED" if "SINK" in outcome else "ALLOW",
                "resolved_ip": resolved_ip,
                "sinkhole_ip": sinkhole_ip,
                "metadata": {
                    "ingested_at_utc": utc_now_iso(),
                },
            }
        )

    if not safe_events:
        return jsonify({"error": "No valid events were provided."}), 400

    stored_count = insert_dns_query_events(safe_events)
    return jsonify(
        {
            "status": "stored",
            "stored_count": stored_count,
            "created_at_utc": utc_now_iso(),
        }
    )


@app.get("/api/reports/latest")
def latest_ioc_report() -> Response:
    report = fetch_latest_ioc_report()
    if report is None:
        return jsonify({"error": "No IOC reports uploaded yet."}), 404
    return jsonify(report)


@app.post("/login")
@limiter.limit("10 per minute")
def login_api() -> Response:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body."}), 400

    username = str(payload.get("username") or "")[:32]
    password = str(payload.get("password") or "")[:72]

    expected_username = "analyst_user"
    expected_password = "CyberLab#2026"

    if not timing_safe_equal(username, expected_username) or not timing_safe_equal(password, expected_password):
        return (
            jsonify(
                {
                    "timestamp_utc": utc_now_iso(),
                    "status": "rejected",
                    "reason": "Invalid credentials.",
                }
            ),
            401,
        )

    token_seed = f"{username}:{utc_now_iso()}".encode("utf-8")
    session_fingerprint = hashlib.sha256(token_seed).hexdigest()
    return jsonify(
        {
            "timestamp_utc": utc_now_iso(),
            "status": "accepted",
            "message": "Login successful (demo mode).",
            "session_fingerprint": session_fingerprint,
        }
    )


@app.post("/api/hash")
@limiter.limit("60 per minute")
def hash_text() -> Response:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body."}), 400

    value = str(payload.get("value") or "")[:1000]
    data = value.encode("utf-8")

    return jsonify(
        {
            "input": value,
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    )


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

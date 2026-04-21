#!/usr/bin/env python3
"""
Dynamic Malware Analysis Sandbox Script (Windows VM)

What this script does:
1) Executes a specified executable sample (the file under analysis).
2) Monitors and logs newly created processes from that sample's process tree.
3) Monitors and logs file create/modify/delete events under C:\\Users\\.
4) Exports all findings as a clean JSON IOC report.

Why extra packages are used:
- psutil: reliable process inspection on Windows.
- watchdog: real-time filesystem event monitoring.
- yara-python (optional): YARA scanning support for dropped files.

Install dependencies inside the isolated VM:
    pip install psutil watchdog
    pip install yara-python  # optional for YARA integration

Example run:
    python dynamic_analysis_sandbox.py --sample "C:\\\\path\\\\to\\\\sample.exe" --duration 120 --output "ioc_report.json"

Safety notes:
- Run ONLY in an isolated analysis VM.
- Prefer snapshots so you can revert quickly after each run.
- Do not run unknown samples on host or production systems.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from socket import SOCK_DGRAM, SOCK_STREAM
from typing import Any, Dict, List, Set, Tuple

# Third-party dependencies (install with: pip install psutil watchdog)
import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

try:
    import yara  # type: ignore
except Exception:
    yara = None


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def safe_process_name(proc: psutil.Process) -> str:
    """
    Read a process name safely.
    Malware or short-lived processes can disappear at any time,
    so we guard against common psutil exceptions.
    """
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "<unavailable>"


def safe_process_cmdline(proc: psutil.Process) -> List[str]:
    """
    Read a process command line safely.
    Returns an empty list if unavailable.
    """
    try:
        return proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []


def safe_ppid(proc: psutil.Process) -> int:
    """Read a process parent PID safely."""
    try:
        return proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return -1


def safe_process_exe(proc: psutil.Process) -> str | None:
    """Read a process executable path safely."""
    try:
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str | None:
    """Compute SHA256 for a file path with streaming reads."""
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def compute_file_hashes(path: str, chunk_size: int = 1024 * 1024) -> Dict[str, str | None]:
    """Compute common file hashes used in threat intelligence sharing."""
    try:
        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        sha256_hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5_hasher.update(chunk)
                sha1_hasher.update(chunk)
                sha256_hasher.update(chunk)
        return {
            "md5": md5_hasher.hexdigest(),
            "sha1": sha1_hasher.hexdigest(),
            "sha256": sha256_hasher.hexdigest(),
        }
    except (OSError, PermissionError):
        return {"md5": None, "sha1": None, "sha256": None}


def is_public_ip(value: str) -> bool:
    """Return True for routable public IPs, False for local/reserved ranges."""
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False



@dataclass
class ProcessEvent:
    """Represents a process creation IOC record."""

    timestamp_utc: str
    pid: int
    ppid: int
    name: str
    cmdline: List[str]
    exe_path: str | None = None
    sha256: str | None = None


@dataclass
class FileEventRecord:
    """Represents a filesystem IOC record."""

    timestamp_utc: str
    event_type: str
    path: str
    is_directory: bool
    destination_path: str | None = None


@dataclass
class NetworkEventRecord:
    """Represents a network IOC record tied to tracked processes."""

    timestamp_utc: str
    pid: int
    process_name: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    is_dns_related: bool


@dataclass
class RegistryEventRecord:
    """Represents a registry IOC from Sysmon event log entries."""

    timestamp_utc: str
    event_id: int
    event_type: str
    process_id: str | None
    image: str | None
    target_object: str | None
    details: str | None


@dataclass
class SecurityAlertRecord:
    """High-signal heuristic alert derived from observed telemetry."""

    timestamp_utc: str
    category: str
    severity: str
    message: str
    mitre_attack_techniques: List[str]
    context: Dict[str, Any]


@dataclass
class YaraMatchRecord:
    """Represents a YARA detection hit on a dropped file."""

    timestamp_utc: str
    file_path: str
    rule: str
    namespace: str
    tags: List[str]


class UsersDirEventHandler(FileSystemEventHandler):
    """
    Custom watchdog event handler.
    Each filesystem event is converted into a serializable record.
    """

    def __init__(self, events: List[FileEventRecord], lock: threading.Lock) -> None:
        super().__init__()
        self._events = events
        self._lock = lock

    def _log_event(self, event_type: str, event: FileSystemEvent) -> None:
        record = FileEventRecord(
            timestamp_utc=utc_now_iso(),
            event_type=event_type,
            path=event.src_path,
            is_directory=event.is_directory,
            destination_path=getattr(event, "dest_path", None),
        )

        # Lock protects shared list access from concurrent observer callbacks.
        with self._lock:
            self._events.append(record)

    def on_created(self, event: FileSystemEvent) -> None:
        self._log_event("created", event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._log_event("modified", event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._log_event("deleted", event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._log_event("moved", event)



class ProcessTreeMonitor:
    """
    Tracks new processes that belong to the malware process tree.

    Logic summary:
    - Start with the initial sample PID as "known and tracked".
    - Poll current process list repeatedly.
    - If a process has a parent PID in our tracked set, it is considered
      part of the observed malware tree and logged once.
    - Newly discovered PIDs are added to the tracked set, allowing us to
      catch grandchildren and deeper descendants.
    """

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self.tracked_tree_pids: Set[int] = {root_pid}
        self.seen_logged_pids: Set[int] = set()
        self.hash_cache: Dict[str, str | None] = {}

    def _sha256_for_exe(self, exe_path: str | None) -> str | None:
        """
        Return cached SHA256 for executable path when possible.
        Caching avoids re-hashing the same binary repeatedly.
        """
        if not exe_path:
            return None
        if exe_path not in self.hash_cache:
            self.hash_cache[exe_path] = sha256_file(exe_path)
        return self.hash_cache[exe_path]

    def collect_new_process_events(self) -> List[ProcessEvent]:
        """
        Return process-creation-like events discovered since last poll.

        This is polling-based monitoring, so very short-lived processes
        can still be missed if they start and end between polls.
        """
        new_events: List[ProcessEvent] = []

        for proc in psutil.process_iter(attrs=["pid", "ppid", "name"]):
            try:
                pid = proc.pid
                ppid = safe_ppid(proc)

                # Skip anything already recorded.
                if pid in self.seen_logged_pids:
                    continue

                # Log if process parent belongs to tracked malware tree.
                if ppid in self.tracked_tree_pids:
                    exe_path = safe_process_exe(proc)
                    event = ProcessEvent(
                        timestamp_utc=utc_now_iso(),
                        pid=pid,
                        ppid=ppid,
                        name=safe_process_name(proc),
                        cmdline=safe_process_cmdline(proc),
                        exe_path=exe_path,
                        sha256=self._sha256_for_exe(exe_path),
                    )
                    new_events.append(event)
                    self.seen_logged_pids.add(pid)
                    self.tracked_tree_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Ignore races and protected processes.
                continue

        return new_events


def build_process_alerts(event: ProcessEvent) -> List[SecurityAlertRecord]:
    """Generate process-based heuristic alerts for common LOLBIN abuse patterns."""
    alerts: List[SecurityAlertRecord] = []
    suspicious_names = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "schtasks.exe",
    }

    name_lower = (event.name or "").lower()
    if name_lower in suspicious_names:
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="process",
                severity="medium",
                message="Suspicious living-off-the-land binary executed in process tree.",
                mitre_attack_techniques=["T1218", "T1059"],
                context={
                    "pid": event.pid,
                    "ppid": event.ppid,
                    "name": event.name,
                    "cmdline": event.cmdline,
                },
            )
        )

    cmdline_text = " ".join(event.cmdline).lower()
    script_markers = ["-enc", "frombase64string", "http://", "https://", "downloadstring"]
    if any(marker in cmdline_text for marker in script_markers):
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="process",
                severity="high",
                message="Potential staged payload or encoded command detected in process arguments.",
                mitre_attack_techniques=["T1059", "T1027", "T1105"],
                context={
                    "pid": event.pid,
                    "name": event.name,
                    "cmdline": event.cmdline,
                },
            )
        )

    return alerts


def build_file_alerts(event: FileEventRecord) -> List[SecurityAlertRecord]:
    """Generate file-system heuristic alerts from suspicious paths and extensions."""
    alerts: List[SecurityAlertRecord] = []
    path_lower = (event.path or "").lower()
    suspicious_exts = (".exe", ".dll", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd")

    if event.event_type in {"created", "modified"} and path_lower.endswith(suspicious_exts):
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="file",
                severity="medium",
                message="Suspicious executable or script file change detected.",
                mitre_attack_techniques=["T1105", "T1204.002"],
                context={
                    "event_type": event.event_type,
                    "path": event.path,
                    "is_directory": event.is_directory,
                },
            )
        )

    startup_markers = [
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    ]
    if any(marker in path_lower for marker in startup_markers):
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="persistence",
                severity="high",
                message="Potential startup-folder persistence artifact detected.",
                mitre_attack_techniques=["T1547.001"],
                context={
                    "event_type": event.event_type,
                    "path": event.path,
                },
            )
        )

    return alerts


def build_network_alerts(event: NetworkEventRecord) -> List[SecurityAlertRecord]:
    """Generate network heuristic alerts for external and suspicious port activity."""
    alerts: List[SecurityAlertRecord] = []

    if is_public_ip(event.remote_ip):
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="network",
                severity="medium",
                message="Connection to routable external IP detected.",
                mitre_attack_techniques=["T1071", "T1041"],
                context={
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "remote_ip": event.remote_ip,
                    "remote_port": event.remote_port,
                    "protocol": event.protocol,
                },
            )
        )

    suspicious_remote_ports = {21, 22, 23, 25, 4444, 5555, 8080, 1337}
    if event.remote_port in suspicious_remote_ports:
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="network",
                severity="high",
                message="Connection observed on commonly abused remote service port.",
                mitre_attack_techniques=["T1071", "T1571"],
                context={
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "remote_ip": event.remote_ip,
                    "remote_port": event.remote_port,
                    "status": event.status,
                },
            )
        )

    if event.is_dns_related and is_public_ip(event.remote_ip):
        alerts.append(
            SecurityAlertRecord(
                timestamp_utc=event.timestamp_utc,
                category="dns",
                severity="medium",
                message="External DNS communication observed from tracked process.",
                mitre_attack_techniques=["T1071.004"],
                context={
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "remote_ip": event.remote_ip,
                    "remote_port": event.remote_port,
                },
            )
        )

    return alerts


def collect_network_events_for_tracked_pids(
    tracked_pids: Set[int],
    seen_connection_keys: Set[Tuple],
) -> List[NetworkEventRecord]:
    """
    Capture new network connection snapshots for tracked process IDs.

    We log only newly seen connection tuples so results are not flooded
    with the same long-lived connection every poll cycle.
    """
    events: List[NetworkEventRecord] = []

    for conn in psutil.net_connections(kind="inet"):
        pid = conn.pid
        if pid is None or pid not in tracked_pids:
            continue

        local_ip = ""
        local_port = 0
        remote_ip = ""
        remote_port = 0

        if conn.laddr:
            local_ip = conn.laddr.ip
            local_port = conn.laddr.port
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

        protocol = "tcp" if conn.type == SOCK_STREAM else "udp" if conn.type == SOCK_DGRAM else "other"
        status = conn.status or "UNKNOWN"
        key = (
            pid,
            protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            status,
        )

        if key in seen_connection_keys:
            continue
        seen_connection_keys.add(key)

        # DNS over classic and encrypted transport ports.
        is_dns_related = remote_port in {53, 853}

        try:
            proc_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            proc_name = "<unavailable>"

        events.append(
            NetworkEventRecord(
                timestamp_utc=utc_now_iso(),
                pid=pid,
                process_name=proc_name,
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=status,
                is_dns_related=is_dns_related,
            )
        )

    return events


def collect_sysmon_registry_events(
    start_time_utc: datetime,
    end_time_utc: datetime,
) -> Tuple[List[RegistryEventRecord], Dict[str, str]]:
    """
    Collect Sysmon registry events (Event IDs 12/13/14) from Windows Event Log.

    Returns:
    - list of registry IOC records
    - status metadata with collection method and notes
    """
    # Event log times are matched in UTC with millisecond precision.
    start_str = start_time_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = end_time_utc.strftime("%Y-%m-%dT%H:%M:%S.999Z")

    query = (
        "*[System[(EventID=12 or EventID=13 or EventID=14) and "
        f"TimeCreated[@SystemTime>='{start_str}' and @SystemTime<='{end_str}']]]"
    )

    cmd = [
        "wevtutil",
        "qe",
        "Microsoft-Windows-Sysmon/Operational",
        "/q:" + query,
        "/f:xml",
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError:
        return [], {
            "method": "sysmon_eventlog",
            "status": "unavailable",
            "note": "wevtutil was not found on this system.",
        }
    except subprocess.TimeoutExpired:
        return [], {
            "method": "sysmon_eventlog",
            "status": "timeout",
            "note": "Timed out while querying Sysmon event log.",
        }

    if completed.returncode != 0:
        note = completed.stderr.strip() or completed.stdout.strip() or "Unknown wevtutil error."
        return [], {
            "method": "sysmon_eventlog",
            "status": "unavailable",
            "note": note,
        }

    xml_text = completed.stdout.strip()
    if not xml_text:
        return [], {
            "method": "sysmon_eventlog",
            "status": "ok",
            "note": "No Sysmon registry events matched the time window.",
        }

    # wevtutil returns multiple <Event> fragments; wrap in one root for parsing.
    wrapped = "<Events>" + xml_text + "</Events>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        return [], {
            "method": "sysmon_eventlog",
            "status": "parse_error",
            "note": f"Failed to parse Sysmon XML output: {exc}",
        }

    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
    id_to_type = {
        12: "registry_object_create_delete",
        13: "registry_value_set",
        14: "registry_key_value_rename",
    }
    records: List[RegistryEventRecord] = []

    for event in root.findall("ev:Event", ns):
        time_node = event.find("ev:System/ev:TimeCreated", ns)
        id_node = event.find("ev:System/ev:EventID", ns)
        if id_node is None:
            continue

        try:
            event_id = int(id_node.text or "0")
        except ValueError:
            event_id = 0

        timestamp = ""
        if time_node is not None:
            timestamp = time_node.attrib.get("SystemTime", "")

        data_map: Dict[str, str] = {}
        for data in event.findall("ev:EventData/ev:Data", ns):
            name = data.attrib.get("Name")
            value = data.text or ""
            if name:
                data_map[name] = value

        records.append(
            RegistryEventRecord(
                timestamp_utc=timestamp,
                event_id=event_id,
                event_type=id_to_type.get(event_id, "registry_event"),
                process_id=data_map.get("ProcessId"),
                image=data_map.get("Image"),
                target_object=data_map.get("TargetObject"),
                details=data_map.get("Details"),
            )
        )

    return records, {
        "method": "sysmon_eventlog",
        "status": "ok",
        "note": "Registry events collected from Microsoft-Windows-Sysmon/Operational.",
    }


def load_yara_rules(yara_rules_path: str) -> Tuple[Any | None, Dict[str, str]]:
    """Load and compile YARA rules if available."""
    if yara is None:
        return None, {
            "method": "yara",
            "status": "unavailable",
            "note": "yara-python is not installed.",
        }

    if not os.path.isfile(yara_rules_path):
        return None, {
            "method": "yara",
            "status": "unavailable",
            "note": f"YARA rules file not found: {yara_rules_path}",
        }

    try:
        compiled_rules = yara.compile(filepath=yara_rules_path)
        return compiled_rules, {
            "method": "yara",
            "status": "ok",
            "note": f"Loaded YARA rules from: {yara_rules_path}",
        }
    except Exception as exc:
        return None, {
            "method": "yara",
            "status": "error",
            "note": f"Failed to compile YARA rules: {exc}",
        }


def collect_dropped_file_candidates(file_events: List[FileEventRecord]) -> Set[str]:
    """Build a set of candidate dropped files from filesystem events."""
    candidates: Set[str] = set()
    for event in file_events:
        if event.is_directory:
            continue
        if event.event_type not in {"created", "modified", "moved"}:
            continue
        if os.path.isfile(event.path):
            candidates.add(event.path)
        if event.destination_path and os.path.isfile(event.destination_path):
            candidates.add(event.destination_path)
    return candidates


def run_yara_scan(compiled_rules: Any, candidate_paths: Set[str]) -> List[YaraMatchRecord]:
    """Execute YARA against candidate dropped files and return detections."""
    matches: List[YaraMatchRecord] = []
    for path in sorted(candidate_paths):
        try:
            yara_matches = compiled_rules.match(path)
        except Exception:
            continue

        for match in yara_matches:
            matches.append(
                YaraMatchRecord(
                    timestamp_utc=utc_now_iso(),
                    file_path=path,
                    rule=getattr(match, "rule", "<unknown>"),
                    namespace=getattr(match, "namespace", "default"),
                    tags=list(getattr(match, "tags", [])),
                )
            )

    return matches


def export_alerts_to_csv(csv_path: str, alerts: List[SecurityAlertRecord]) -> None:
    """Write heuristic security alerts into a CSV file for analyst workflows."""
    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "timestamp_utc",
                "category",
                "severity",
                "message",
                "mitre_attack_techniques",
                "context_json",
            ],
        )
        writer.writeheader()
        for alert in alerts:
            writer.writerow(
                {
                    "timestamp_utc": alert.timestamp_utc,
                    "category": alert.category,
                    "severity": alert.severity,
                    "message": alert.message,
                    "mitre_attack_techniques": ";".join(alert.mitre_attack_techniques),
                    "context_json": json.dumps(alert.context, ensure_ascii=True),
                }
            )



def run_analysis(
    sample_path: str,
    duration_seconds: int,
    output_path: str,
    enable_yara: bool = False,
    yara_rules_path: str | None = None,
    alerts_csv_path: str | None = None,
) -> Dict:
    """
    Execute the sample and monitor activity for the configured duration.

    Returns a dictionary ready for JSON serialization.
    """
    analysis_start_dt = datetime.now(timezone.utc)
    analysis_start = analysis_start_dt.isoformat()

    # Validate sample path before launching.
    if not os.path.isfile(sample_path):
        raise FileNotFoundError(f"Sample does not exist or is not a file: {sample_path}")

    # Shared event stores and lock for thread-safe writes.
    file_events: List[FileEventRecord] = []
    process_events: List[ProcessEvent] = []
    network_events: List[NetworkEventRecord] = []
    security_alerts: List[SecurityAlertRecord] = []
    file_lock = threading.Lock()
    seen_connection_keys: Set[Tuple] = set()

    # Set up filesystem observer for C:\Users recursively.
    users_root = r"C:\Users"
    handler = UsersDirEventHandler(file_events, file_lock)
    observer = Observer()
    observer.schedule(handler, path=users_root, recursive=True)

    # Start observer before launching sample to avoid missing early events.
    observer.start()

    # Launch the sample process in its own process group.
    # CREATE_NEW_PROCESS_GROUP can help with later control if needed.
    creationflags = 0x00000200 if os.name == "nt" else 0
    sample_proc = subprocess.Popen(
        [sample_path],
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )

    process_monitor = ProcessTreeMonitor(root_pid=sample_proc.pid)

    # Also log the root process itself as the initial execution IOC.
    try:
        root_ps = psutil.Process(sample_proc.pid)
        root_exe = safe_process_exe(root_ps)
        process_events.append(
            ProcessEvent(
                timestamp_utc=utc_now_iso(),
                pid=sample_proc.pid,
                ppid=safe_ppid(root_ps),
                name=safe_process_name(root_ps),
                cmdline=safe_process_cmdline(root_ps),
                exe_path=root_exe,
                sha256=process_monitor._sha256_for_exe(root_exe),
            )
        )
        security_alerts.extend(build_process_alerts(process_events[-1]))
        process_monitor.seen_logged_pids.add(sample_proc.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    poll_interval_seconds = 1.0
    end_time = time.time() + duration_seconds

    try:
        while time.time() < end_time:
            # Gather newly discovered child/descendant processes.
            new_proc_events = process_monitor.collect_new_process_events()
            process_events.extend(new_proc_events)
            for event in new_proc_events:
                security_alerts.extend(build_process_alerts(event))

            # Gather network activity for tracked process tree members.
            new_network_events = collect_network_events_for_tracked_pids(
                process_monitor.tracked_tree_pids,
                seen_connection_keys,
            )
            network_events.extend(new_network_events)
            for event in new_network_events:
                security_alerts.extend(build_network_alerts(event))

            with file_lock:
                recent_file_events = file_events[-25:]
            for event in recent_file_events:
                security_alerts.extend(build_file_alerts(event))

            time.sleep(poll_interval_seconds)
    finally:
        # Stop filesystem watcher first.
        observer.stop()
        observer.join(timeout=10)

        # Best effort termination of root sample process if still running.
        if sample_proc.poll() is None:
            try:
                sample_proc.terminate()
                sample_proc.wait(timeout=5)
            except Exception:
                try:
                    sample_proc.kill()
                except Exception:
                    pass

    analysis_end_dt = datetime.now(timezone.utc)
    analysis_end = analysis_end_dt.isoformat()

    # Sysmon-assisted registry collection from Windows Event Log.
    registry_events, registry_collection_status = collect_sysmon_registry_events(
        analysis_start_dt,
        analysis_end_dt,
    )

    yara_matches: List[YaraMatchRecord] = []
    if enable_yara:
        rules_path = os.path.abspath(yara_rules_path or "yara_rules.yar")
        compiled_rules, yara_collection_status = load_yara_rules(rules_path)
        if compiled_rules is not None:
            dropped_candidates = collect_dropped_file_candidates(file_events)
            yara_matches = run_yara_scan(compiled_rules, dropped_candidates)
    else:
        yara_collection_status = {
            "method": "yara",
            "status": "disabled",
            "note": "YARA scanning disabled by CLI option.",
        }

    sample_hashes = compute_file_hashes(sample_path)

    # De-duplicate repeated alerts produced across polling cycles.
    deduped_alerts: List[SecurityAlertRecord] = []
    seen_alert_keys: Set[Tuple[str, str, str]] = set()
    for alert in security_alerts:
        key = (alert.category, alert.message, json.dumps(alert.context, sort_keys=True))
        if key in seen_alert_keys:
            continue
        seen_alert_keys.add(key)
        deduped_alerts.append(alert)

    # Build a clean JSON-friendly report structure.
    report = {
        "metadata": {
            "analysis_start_utc": analysis_start,
            "analysis_end_utc": analysis_end,
            "analysis_duration_seconds": duration_seconds,
            "sample_path": sample_path,
            "sample_filename": os.path.basename(sample_path),
            "sample_hashes": sample_hashes,
            "host": {
                "platform": sys.platform,
                "python_version": sys.version,
            },
        },
        "iocs": {
            "process_events": [asdict(evt) for evt in process_events],
            "file_events_under_c_users": [asdict(evt) for evt in file_events],
            "network_events": [asdict(evt) for evt in network_events],
            "dns_related_network_events": [
                asdict(evt) for evt in network_events if evt.is_dns_related
            ],
            "registry_events": [asdict(evt) for evt in registry_events],
            "security_alerts": [asdict(evt) for evt in deduped_alerts],
            "yara_matches": [asdict(evt) for evt in yara_matches],
        },
        "summary": {
            "process_event_count": len(process_events),
            "file_event_count": len(file_events),
            "network_event_count": len(network_events),
            "dns_event_count": len([evt for evt in network_events if evt.is_dns_related]),
            "registry_event_count": len(registry_events),
            "security_alert_count": len(deduped_alerts),
            "yara_match_count": len(yara_matches),
            "notes": [
                "Process tracking is polling-based and may miss extremely short-lived processes.",
                "Filesystem monitoring is scoped to C:\\Users recursively.",
                "Network tracking uses psutil.net_connections(kind='inet') snapshots and may miss very short-lived sockets.",
                "Registry tracking is Sysmon-assisted and requires Sysmon with registry event IDs 12/13/14 enabled.",
                "Security alerts are heuristic signals and should be triaged with analyst review.",
            ],
        },
        "collection_status": {
            "registry": registry_collection_status,
            "yara": yara_collection_status,
        },
    }

    if alerts_csv_path:
        export_alerts_to_csv(alerts_csv_path, deduped_alerts)

    # Write report with indentation for readability.
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dynamic malware analysis helper for isolated Windows VMs."
    )
    parser.add_argument(
        "--sample",
        required=True,
        help="Full path to executable sample to run and monitor.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Monitoring duration in seconds (default: 120).",
    )
    parser.add_argument(
        "--output",
        default="ioc_report.json",
        help="Output JSON report path (default: ioc_report.json).",
    )
    parser.add_argument(
        "--enable-yara",
        action="store_true",
        help="Enable YARA scanning for dropped files using --yara-rules.",
    )
    parser.add_argument(
        "--yara-rules",
        default="yara_rules.yar",
        help="Path to YARA rules file (default: yara_rules.yar).",
    )
    parser.add_argument(
        "--alerts-csv",
        default=None,
        help="Optional CSV path to export heuristic security alerts.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        # Normalize paths for cleaner report output.
        sample_path = os.path.abspath(args.sample)
        output_path = os.path.abspath(args.output)

        run_analysis(
            sample_path=sample_path,
            duration_seconds=args.duration,
            output_path=output_path,
            enable_yara=args.enable_yara,
            yara_rules_path=os.path.abspath(args.yara_rules) if args.yara_rules else None,
            alerts_csv_path=os.path.abspath(args.alerts_csv) if args.alerts_csv else None,
        )

        print(f"[+] Analysis complete. JSON IOC report written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"[!] Analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

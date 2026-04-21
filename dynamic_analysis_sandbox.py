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

Install dependencies inside the isolated VM:
    pip install psutil watchdog

Example run:
    python dynamic_analysis_sandbox.py --sample "C:\\\\path\\\\to\\\\sample.exe" --duration 120 --output "ioc_report.json"

Safety notes:
- Run ONLY in an isolated analysis VM.
- Prefer snapshots so you can revert quickly after each run.
- Do not run unknown samples on host or production systems.
"""

from __future__ import annotations

import argparse
import hashlib
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
from typing import Dict, List, Set, Tuple

# Third-party dependencies (install with: pip install psutil watchdog)
import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


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



def run_analysis(sample_path: str, duration_seconds: int, output_path: str) -> Dict:
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

            # Gather network activity for tracked process tree members.
            new_network_events = collect_network_events_for_tracked_pids(
                process_monitor.tracked_tree_pids,
                seen_connection_keys,
            )
            network_events.extend(new_network_events)

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

    # Build a clean JSON-friendly report structure.
    report = {
        "metadata": {
            "analysis_start_utc": analysis_start,
            "analysis_end_utc": analysis_end,
            "analysis_duration_seconds": duration_seconds,
            "sample_path": sample_path,
            "sample_filename": os.path.basename(sample_path),
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
        },
        "summary": {
            "process_event_count": len(process_events),
            "file_event_count": len(file_events),
            "network_event_count": len(network_events),
            "dns_event_count": len([evt for evt in network_events if evt.is_dns_related]),
            "registry_event_count": len(registry_events),
            "notes": [
                "Process tracking is polling-based and may miss extremely short-lived processes.",
                "Filesystem monitoring is scoped to C:\\Users recursively.",
                "Network tracking uses psutil.net_connections(kind='inet') snapshots and may miss very short-lived sockets.",
                "Registry tracking is Sysmon-assisted and requires Sysmon with registry event IDs 12/13/14 enabled.",
            ],
        },
        "collection_status": {
            "registry": registry_collection_status,
        },
    }

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
        )

        print(f"[+] Analysis complete. JSON IOC report written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"[!] Analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

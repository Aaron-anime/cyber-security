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
import ctypes
import csv
import hashlib
import ipaddress
import json
import math
import os
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from socket import SOCK_DGRAM, SOCK_STREAM
from typing import Any, Dict, List, Set, Tuple

try:
    import winreg  # type: ignore
except Exception:
    winreg = None

from ctypes import wintypes

# Third-party dependencies (install with: pip install psutil watchdog)
import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

try:
    import yara  # type: ignore
except Exception:
    yara = None

try:
    import mss  # type: ignore
except Exception:
    mss = None

try:
    from PIL import ImageGrab  # type: ignore
except Exception:
    ImageGrab = None


VM_REGISTRY_PATH = r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
KNOWN_VM_ARTIFACT_PATHS = [
    r"C:\Windows\System32\drivers\vmmouse.sys",
    r"C:\Windows\System32\drivers\vmhgfs.sys",
    r"C:\Windows\System32\drivers\VBoxMouse.sys",
    r"C:\Windows\System32\drivers\VBoxGuest.sys",
]

JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
DEBUG_PROCESS = 0x00000001


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class WindowsProcessHandle:
    """Small helper around native Windows process/thread handles."""

    def __init__(self, process_handle: int, thread_handle: int, pid: int) -> None:
        self.process_handle = int(process_handle)
        self.thread_handle = int(thread_handle)
        self.pid = int(pid)

    def poll(self) -> int | None:
        if os.name != "nt":
            return None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        wait_result = kernel32.WaitForSingleObject(wintypes.HANDLE(self.process_handle), wintypes.DWORD(0))
        WAIT_OBJECT_0 = 0
        WAIT_TIMEOUT = 0x00000102
        if wait_result == WAIT_TIMEOUT:
            return None
        if wait_result == WAIT_OBJECT_0:
            exit_code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(wintypes.HANDLE(self.process_handle), ctypes.byref(exit_code))
            return int(exit_code.value)
        return None

    def close_handles(self) -> None:
        if os.name != "nt":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if self.thread_handle:
            kernel32.CloseHandle(wintypes.HANDLE(self.thread_handle))
            self.thread_handle = 0
        if self.process_handle:
            kernel32.CloseHandle(wintypes.HANDLE(self.process_handle))
            self.process_handle = 0


def launch_windows_process_suspended(sample_path: str, debug_process: bool) -> WindowsProcessHandle:
    """Launch a Windows process suspended so Job Object assignment can happen before execution."""
    if os.name != "nt":
        raise RuntimeError("Suspended launch is only supported on Windows.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_process = kernel32.CreateProcessW
    create_process.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    create_process.restype = wintypes.BOOL

    creationflags = CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED
    if debug_process:
        creationflags |= DEBUG_PROCESS

    startup_info = STARTUPINFOW()
    startup_info.cb = ctypes.sizeof(STARTUPINFOW)
    proc_info = PROCESS_INFORMATION()

    command_line_buffer = ctypes.create_unicode_buffer(subprocess.list2cmdline([sample_path]))
    current_dir = os.path.dirname(sample_path) or None

    ok = create_process(
        sample_path,
        command_line_buffer,
        None,
        None,
        False,
        creationflags,
        None,
        current_dir,
        ctypes.byref(startup_info),
        ctypes.byref(proc_info),
    )
    if not ok:
        code = ctypes.get_last_error()
        raise RuntimeError(f"CreateProcessW failed with code {code}.")

    return WindowsProcessHandle(
        process_handle=int(proc_info.hProcess),
        thread_handle=int(proc_info.hThread),
        pid=int(proc_info.dwProcessId),
    )


def resume_windows_process(proc: WindowsProcessHandle) -> None:
    """Resume primary thread of a suspended Windows process."""
    if os.name != "nt":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = [wintypes.HANDLE]
    resume_thread.restype = wintypes.DWORD
    result = resume_thread(wintypes.HANDLE(proc.thread_handle))
    if result == 0xFFFFFFFF:
        code = ctypes.get_last_error()
        raise RuntimeError(f"ResumeThread failed with code {code}.")


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


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy for a byte sequence.
    
    Returns a value 0.0-8.0 indicating randomness/compression.
    High entropy (>7.0) suggests encryption or compression.
    """
    if not data:
        return 0.0
    
    byte_counts: Dict[int, int] = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    length = len(data)
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


class TTLNetworkCache:
    """
    TTL-based cache for deduplicating network connections by time window.
    
    Stores (timestamp, pid, protocol, local_ip, local_port, remote_ip, remote_port)
    tuples and expires entries older than ttl_seconds.
    """
    
    def __init__(self, ttl_seconds: float = 30.0):
        self.ttl_seconds = ttl_seconds
        self.entries: Dict[Tuple, float] = {}
    
    def should_log(self, key: Tuple, current_time: float) -> bool:
        """Return True if key should be logged (not in cache or expired)."""
        if key in self.entries:
            entry_age = current_time - self.entries[key]
            if entry_age < self.ttl_seconds:
                return False
        
        # Cleanup old entries periodically
        if len(self.entries) > 1000:
            expired_keys = [k for k, t in self.entries.items() 
                          if current_time - t >= self.ttl_seconds]
            for k in expired_keys:
                del self.entries[k]
        
        self.entries[key] = current_time
        return True


def capture_desktop_screenshot(output_dir: str, prefix: str = "screenshot") -> Dict[str, str]:
    """
    Capture a screenshot of the desktop for visual forensics.
    
    Tries PIL.ImageGrab first, then falls back to mss if available.
    Returns metadata dict with capture method and status.
    """
    if not os.path.isdir(output_dir):
        return {
            "method": "screenshot",
            "status": "error",
            "note": f"Output directory does not exist: {output_dir}",
        }
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.png"
    filepath = os.path.join(output_dir, filename)
    
    try:
        if ImageGrab is not None:
            try:
                img = ImageGrab.grab()
                img.save(filepath)
                return {
                    "method": "screenshot",
                    "status": "ok",
                    "note": f"Captured with PIL.ImageGrab: {filepath}",
                }
            except Exception as e:
                pass
        
        if mss is not None:
            try:
                with mss.mss() as sct:
                    monitor = sct.monitors[1]
                    screenshot = sct.grab(monitor)
                    mss.tools.to_png(screenshot.rgb, screenshot.size, output=filepath)
                    return {
                        "method": "screenshot",
                        "status": "ok",
                        "note": f"Captured with mss: {filepath}",
                    }
            except Exception as e:
                pass
        
        return {
            "method": "screenshot",
            "status": "unavailable",
            "note": "Neither PIL nor mss available. Install with: pip install Pillow mss",
        }
    except Exception as e:
        return {
            "method": "screenshot",
            "status": "error",
            "note": f"Screenshot capture failed: {e}",
        }


def calculate_process_risk_score(event: ProcessEvent) -> float:
    """
    Calculate risk score for a process event (0.0-100.0).
    
    Considers: parent-child relationship, suspicious names, encoded commands.
    """
    score = 10.0
    
    suspicious_exes = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "schtasks.exe", "tasksched.exe"
    }
    
    if (event.name or "").lower() in suspicious_exes:
        score += 25.0
    
    cmdline_text = " ".join(event.cmdline).lower()
    if "-enc" in cmdline_text or "frombase64string" in cmdline_text:
        score += 30.0
    if "http://" in cmdline_text or "https://" in cmdline_text:
        score += 20.0
    
    return min(score, 100.0)


def calculate_file_risk_score(event: FileEventRecord) -> float:
    """
    Calculate risk score for a file event (0.0-100.0).
    
    Considers: event type, file extension, entropy, suspicious paths.
    """
    score = 5.0
    
    suspicious_exts = {".exe", ".dll", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".scr"}
    path_lower = (event.path or "").lower()
    
    if any(path_lower.endswith(ext) for ext in suspicious_exts):
        score += 30.0
    
    if event.entropy is not None and event.entropy > 7.0:
        score += 20.0
    
    startup_markers = [
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
        "\\programdata\\microsoft\\windows\\start menu\\programs\\startup"
    ]
    if any(marker in path_lower for marker in startup_markers):
        score += 40.0
    
    return min(score, 100.0)


def calculate_network_risk_score(event: NetworkEventRecord) -> float:
    """
    Calculate risk score for a network event (0.0-100.0).
    
    Considers: public IP, suspicious ports, DNS tunneling indicators.
    """
    score = 5.0
    
    if is_public_ip(event.remote_ip):
        score += 25.0
    
    suspicious_ports = {21, 22, 23, 25, 4444, 5555, 8080, 1337, 443, 8443}
    if event.remote_port in suspicious_ports:
        score += 20.0
    
    if event.is_dns_related and is_public_ip(event.remote_ip):
        score += 30.0
    
    return min(score, 100.0)


def detect_c2_beaconing(network_events: List[NetworkEventRecord]) -> Dict[str, Any]:
    """
    Detect potential C2 beaconing patterns from network events.
    
    Looks for: high-frequency DNS queries, repeated connections to same host,
    connection persistence patterns.
    
    Returns dict with detected patterns and confidence scores.
    """
    beaconing_indicators = {
        "high_frequency_dns": [],
        "repeated_connections": [],
        "connection_persistence": [],
        "confidence_score": 0.0,
    }
    
    # Group by (pid, protocol, remote_ip, remote_port)
    connection_groups: Dict[Tuple, List[NetworkEventRecord]] = defaultdict(list)
    for event in network_events:
        key = (event.pid, event.protocol, event.remote_ip, event.remote_port)
        connection_groups[key].append(event)
    
    dns_query_counts: Dict[Tuple[int, str], int] = defaultdict(int)
    for event in network_events:
        if event.is_dns_related:
            key = (event.pid, event.remote_ip)
            dns_query_counts[key] += 1
    
    # Detect high-frequency DNS queries (>10 unique queries to same IP)
    for (pid, dns_ip), count in dns_query_counts.items():
        if count > 10:
            beaconing_indicators["high_frequency_dns"].append({
                "pid": pid,
                "remote_dns_ip": dns_ip,
                "query_count": count,
                "confidence": min(count / 50.0, 1.0),
            })
    
    # Detect repeated connections (same remote host multiple times)
    for (pid, protocol, remote_ip, remote_port), events in connection_groups.items():
        if len(events) > 5 and protocol == "tcp":
            event_times = [datetime.fromisoformat(e.timestamp_utc) for e in events]
            event_times.sort()
            
            if len(event_times) >= 3:
                intervals = []
                for i in range(len(event_times) - 1):
                    delta = (event_times[i+1] - event_times[i]).total_seconds()
                    intervals.append(delta)
                
                avg_interval = sum(intervals) / len(intervals)
                if 5 < avg_interval < 3600:
                    beaconing_indicators["repeated_connections"].append({
                        "pid": pid,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "connection_count": len(events),
                        "avg_interval_seconds": avg_interval,
                        "confidence": min(len(events) / 20.0, 1.0),
                    })
    
    # Calculate overall confidence
    if beaconing_indicators["high_frequency_dns"]:
        beaconing_indicators["confidence_score"] += 0.4
    if beaconing_indicators["repeated_connections"]:
        beaconing_indicators["confidence_score"] += 0.6
    
    beaconing_indicators["confidence_score"] = min(beaconing_indicators["confidence_score"], 1.0)
    
    return beaconing_indicators



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
    risk_score: float = 0.0


@dataclass
class FileEventRecord:
    """Represents a filesystem IOC record."""

    timestamp_utc: str
    event_type: str
    path: str
    is_directory: bool
    destination_path: str | None = None
    entropy: float | None = None
    risk_score: float = 0.0


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
    risk_score: float = 0.0
    beacon_confidence: float = 0.0


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
    risk_score: float = 0.0


@dataclass
class SysmonApiEventRecord:
    """Represents high-signal Sysmon events tied to code injection or remote thread behavior."""

    timestamp_utc: str
    event_id: int
    event_type: str
    process_id: str | None
    image: str | None
    target_process_id: str | None
    target_image: str | None
    source_process_guid: str | None
    target_process_guid: str | None
    start_address: str | None
    details: str | None
    risk_score: float = 0.0


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


def check_vm_isolation() -> Tuple[bool, Dict[str, Any]]:
    """Return whether host appears to be a VM using registry key + artifact checks."""
    evidence: Dict[str, Any] = {
        "registry_key_found": False,
        "artifact_paths_found": [],
    }

    if os.name != "nt":
        return False, {"status": "unsupported_platform", **evidence}

    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, VM_REGISTRY_PATH):
                evidence["registry_key_found"] = True
        except OSError:
            pass

    found_artifacts = [path for path in KNOWN_VM_ARTIFACT_PATHS if os.path.exists(path)]
    evidence["artifact_paths_found"] = found_artifacts

    is_vm = bool(evidence["registry_key_found"] or found_artifacts)
    return is_vm, {"status": "ok", **evidence}


def sanitize_csv_field(value: str) -> str:
    """Mitigate CSV formula injection by neutralizing risky leading characters."""
    if value and value[0] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def validate_rules_path(yara_rules_path: str, allowed_directory: str) -> str:
    """Constrain YARA rule files to a trusted directory root."""
    candidate = os.path.abspath(yara_rules_path)
    allowed_root = os.path.abspath(allowed_directory)
    common = os.path.commonpath([candidate, allowed_root])
    if common != allowed_root:
        raise ValueError(
            f"YARA rules path is outside allowed directory. path={candidate}, allowed={allowed_root}"
        )
    return candidate


def terminate_process_tree(root_pid: int, timeout_seconds: int) -> None:
    """Terminate tracked root process and descendants with bounded wait time."""
    try:
        root = psutil.Process(root_pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return

    descendants = root.children(recursive=True)
    for proc in descendants:
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    try:
        root.terminate()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    gone, alive = psutil.wait_procs(descendants + [root], timeout=max(1, timeout_seconds))
    _ = gone
    for proc in alive:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


def create_and_assign_job_object(
    process_handle: int,
    max_active_processes: int,
) -> Tuple[int | None, Dict[str, str]]:
    """Create a Windows Job Object and assign the process for kernel-enforced containment."""
    if os.name != "nt":
        return None, {
            "method": "windows_job_object",
            "status": "unsupported_platform",
            "note": "Job Objects are Windows-only.",
        }

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job_object = kernel32.CreateJobObjectW
    set_information = kernel32.SetInformationJobObject
    assign_process = kernel32.AssignProcessToJobObject
    close_handle = kernel32.CloseHandle

    create_job_object.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job_object.restype = wintypes.HANDLE
    set_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_information.restype = wintypes.BOOL
    assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign_process.restype = wintypes.BOOL
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    job_handle = create_job_object(None, None)
    if not job_handle:
        code = ctypes.get_last_error()
        return None, {
            "method": "windows_job_object",
            "status": "error",
            "note": f"CreateJobObjectW failed with code {code}.",
        }

    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    )
    limits.BasicLimitInformation.ActiveProcessLimit = max(1, int(max_active_processes))

    ok = set_information(
        job_handle,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    )
    if not ok:
        code = ctypes.get_last_error()
        close_handle(job_handle)
        return None, {
            "method": "windows_job_object",
            "status": "error",
            "note": f"SetInformationJobObject failed with code {code}.",
        }

    ok = assign_process(job_handle, wintypes.HANDLE(process_handle))
    if not ok:
        code = ctypes.get_last_error()
        close_handle(job_handle)
        return None, {
            "method": "windows_job_object",
            "status": "error",
            "note": f"AssignProcessToJobObject failed with code {code}.",
        }

    return int(job_handle), {
        "method": "windows_job_object",
        "status": "ok",
        "note": f"Assigned process to Job Object with ActiveProcessLimit={max_active_processes} and KillOnJobClose.",
    }


def close_job_object(job_handle: int | None) -> None:
    """Close job handle to trigger KILL_ON_JOB_CLOSE behavior."""
    if not job_handle:
        return
    if os.name != "nt":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(wintypes.HANDLE(job_handle))


def maybe_dump_process_memory(
    pid: int,
    output_dir: str,
    enabled: bool,
    procdump_path: str,
) -> Dict[str, str]:
    """Optionally capture a full process memory dump using procdump if available."""
    if not enabled:
        return {
            "method": "procdump",
            "status": "disabled",
            "note": "Memory dump disabled by CLI option.",
        }

    resolved_proc_dump = shutil.which(procdump_path) or procdump_path
    if not os.path.exists(resolved_proc_dump):
        return {
            "method": "procdump",
            "status": "unavailable",
            "note": f"ProcDump executable not found: {procdump_path}",
        }

    os.makedirs(output_dir, exist_ok=True)
    dump_path = os.path.join(output_dir, f"sample_{pid}.dmp")
    cmd = [resolved_proc_dump, "-accepteula", "-ma", str(pid), dump_path]

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=45)
    except subprocess.TimeoutExpired:
        return {
            "method": "procdump",
            "status": "timeout",
            "note": "ProcDump timed out while collecting memory.",
        }
    except Exception as exc:
        return {
            "method": "procdump",
            "status": "error",
            "note": f"ProcDump execution failed: {exc}",
        }

    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "Unknown ProcDump error"
        return {
            "method": "procdump",
            "status": "error",
            "note": message,
        }

    return {
        "method": "procdump",
        "status": "ok",
        "note": f"Memory dump written to: {dump_path}",
    }


def collect_sysmon_events(
    event_ids: List[int],
    start_time_utc: datetime,
    end_time_utc: datetime,
    timeout_seconds: int = 30,
) -> Tuple[List[ET.Element], Dict[str, str]]:
    """Collect Sysmon XML event nodes for requested event IDs in time window."""
    start_str = start_time_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = end_time_utc.strftime("%Y-%m-%dT%H:%M:%S.999Z")
    id_clause = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    query = (
        "*[System[(" + id_clause + ") and "
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
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return [], {"status": "unavailable", "note": "wevtutil was not found on this system."}
    except subprocess.TimeoutExpired:
        return [], {"status": "timeout", "note": "Timed out while querying Sysmon event log."}

    if completed.returncode != 0:
        note = completed.stderr.strip() or completed.stdout.strip() or "Unknown wevtutil error."
        return [], {"status": "unavailable", "note": note}

    xml_text = completed.stdout.strip()
    if not xml_text:
        return [], {"status": "ok", "note": "No Sysmon events matched the time window."}

    wrapped = "<Events>" + xml_text + "</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        return [], {"status": "parse_error", "note": f"Failed to parse Sysmon XML output: {exc}"}

    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
    nodes = root.findall("ev:Event", ns)
    return nodes, {"status": "ok", "note": "Sysmon events collected."}


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
                    
                    # Calculate risk score
                    event.risk_score = calculate_process_risk_score(event)
                    
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
    ttl_cache: TTLNetworkCache,
) -> List[NetworkEventRecord]:
    """
    Capture new network connection snapshots for tracked process IDs.

    Uses TTL-based deduplication so connections are re-logged after ttl_seconds.
    This prevents missing reconnections and periodic beaconing patterns.
    """
    events: List[NetworkEventRecord] = []
    current_time = time.time()

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
        
        # Use TTL cache instead of simple set dedup
        key = (
            pid,
            protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        )

        if not ttl_cache.should_log(key, current_time):
            continue

        # DNS over classic and encrypted transport ports.
        is_dns_related = remote_port in {53, 853}

        try:
            proc_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            proc_name = "<unavailable>"

        network_event = NetworkEventRecord(
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
        
        # Calculate risk score
        network_event.risk_score = calculate_network_risk_score(network_event)
        
        events.append(network_event)

    return events


def collect_sysmon_registry_events(
    start_time_utc: datetime,
    end_time_utc: datetime,
    tracked_process_exes: Set[str] | None = None,
) -> Tuple[List[RegistryEventRecord], Dict[str, str]]:
    """
    Collect Sysmon registry events (Event IDs 12/13/14) from Windows Event Log.

    If tracked_process_exes is provided, filters events to only include those
    from processes in the tracked process tree.
    
    Returns:
    - list of registry IOC records
    - status metadata with collection method and notes
    """
    nodes, status = collect_sysmon_events(
        event_ids=[12, 13, 14],
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        timeout_seconds=30,
    )
    if status["status"] != "ok":
        return [], {
            "method": "sysmon_eventlog",
            "status": status["status"],
            "note": status["note"],
        }

    if not nodes:
        return [], {
            "method": "sysmon_eventlog",
            "status": "ok",
            "note": "No Sysmon registry events matched the time window.",
        }

    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
    id_to_type = {
        12: "registry_object_create_delete",
        13: "registry_value_set",
        14: "registry_key_value_rename",
    }
    records: List[RegistryEventRecord] = []

    for event in nodes:
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

        # Filter by process tree if provided
        if tracked_process_exes is not None:
            image_path = data_map.get("Image", "").lower()
            if not any(exe.lower() in image_path for exe in tracked_process_exes):
                continue

        registry_event = RegistryEventRecord(
            timestamp_utc=timestamp,
            event_id=event_id,
            event_type=id_to_type.get(event_id, "registry_event"),
            process_id=data_map.get("ProcessId"),
            image=data_map.get("Image"),
            target_object=data_map.get("TargetObject"),
            details=data_map.get("Details"),
        )
        
        # Calculate registry risk score based on target object
        target_obj = data_map.get("TargetObject", "").lower()
        if any(s in target_obj for s in ["run", "startup", "policy", "services"]):
            registry_event.risk_score = min(70.0, 100.0)
        elif "hklm" in target_obj:
            registry_event.risk_score = 40.0
        else:
            registry_event.risk_score = 20.0
        
        records.append(registry_event)

    return records, {
        "method": "sysmon_eventlog",
        "status": "ok",
        "note": "Registry events collected from Microsoft-Windows-Sysmon/Operational.",
    }


def collect_sysmon_api_events(
    start_time_utc: datetime,
    end_time_utc: datetime,
) -> Tuple[List[SysmonApiEventRecord], Dict[str, str]]:
    """Collect Sysmon events for process/thread/code-injection related IDs."""
    nodes, status = collect_sysmon_events(
        event_ids=[1, 7, 8, 10, 25],
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        timeout_seconds=35,
    )
    if status["status"] != "ok":
        return [], {
            "method": "sysmon_api_events",
            "status": status["status"],
            "note": status["note"],
        }

    if not nodes:
        return [], {
            "method": "sysmon_api_events",
            "status": "ok",
            "note": "No Sysmon API-related events matched the time window.",
        }

    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
    id_to_type = {
        1: "process_create",
        7: "image_load",
        8: "create_remote_thread",
        10: "process_access",
        25: "process_tampering",
    }
    records: List[SysmonApiEventRecord] = []

    for event in nodes:
        event_id_node = event.find("ev:System/ev:EventID", ns)
        time_node = event.find("ev:System/ev:TimeCreated", ns)
        if event_id_node is None:
            continue

        try:
            event_id = int(event_id_node.text or "0")
        except ValueError:
            event_id = 0

        timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
        data_map: Dict[str, str] = {}
        for data in event.findall("ev:EventData/ev:Data", ns):
            name = data.attrib.get("Name")
            value = data.text or ""
            if name:
                data_map[name] = value

        records.append(
            SysmonApiEventRecord(
                timestamp_utc=timestamp,
                event_id=event_id,
                event_type=id_to_type.get(event_id, "api_event"),
                process_id=data_map.get("ProcessId") or data_map.get("SourceProcessId"),
                image=data_map.get("Image") or data_map.get("SourceImage"),
                target_process_id=data_map.get("TargetProcessId"),
                target_image=data_map.get("TargetImage"),
                source_process_guid=data_map.get("SourceProcessGuid"),
                target_process_guid=data_map.get("TargetProcessGuid"),
                start_address=data_map.get("StartAddress"),
                details=data_map.get("GrantedAccess") or data_map.get("CallTrace") or data_map.get("Hashes"),
            )
        )

    return records, {
        "method": "sysmon_api_events",
        "status": "ok",
        "note": "Sysmon event IDs 1,7,8,10,25 collected.",
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


def collect_dropped_file_candidates(file_events: List[FileEventRecord]) -> Dict[str, FileEventRecord]:
    """
    Build a dict of candidate dropped files from filesystem events.
    
    Reads file content to calculate Shannon entropy and assigns risk scores.
    Returns dict mapping file path to FileEventRecord with entropy calculated.
    """
    candidates: Dict[str, FileEventRecord] = {}
    
    for event in file_events:
        if event.is_directory:
            continue
        if event.event_type not in {"created", "modified", "moved"}:
            continue
        
        # Check event.path
        if os.path.isfile(event.path):
            if event.path not in candidates:
                try:
                    with open(event.path, "rb") as f:
                        data = f.read(1024 * 100)  # Sample first 100KB
                        event.entropy = calculate_shannon_entropy(data)
                        event.risk_score = calculate_file_risk_score(event)
                except Exception:
                    pass
                candidates[event.path] = event
        
        # Check destination_path
        if event.destination_path and os.path.isfile(event.destination_path):
            if event.destination_path not in candidates:
                dest_event = FileEventRecord(
                    timestamp_utc=event.timestamp_utc,
                    event_type=event.event_type,
                    path=event.destination_path,
                    is_directory=False,
                    destination_path=None,
                )
                try:
                    with open(event.destination_path, "rb") as f:
                        data = f.read(1024 * 100)
                        dest_event.entropy = calculate_shannon_entropy(data)
                        dest_event.risk_score = calculate_file_risk_score(dest_event)
                except Exception:
                    pass
                candidates[event.destination_path] = dest_event
    
    return candidates


def run_yara_scan(compiled_rules: Any, candidate_paths: Dict[str, FileEventRecord]) -> List[YaraMatchRecord]:
    """Execute YARA against candidate dropped files and return detections."""
    matches: List[YaraMatchRecord] = []
    for path in sorted(candidate_paths.keys()):
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
            quoting=csv.QUOTE_NONNUMERIC,
        )
        writer.writeheader()
        for alert in alerts:
            writer.writerow(
                {
                    "timestamp_utc": alert.timestamp_utc,
                    "category": sanitize_csv_field(alert.category),
                    "severity": sanitize_csv_field(alert.severity),
                    "message": sanitize_csv_field(alert.message),
                    "mitre_attack_techniques": ";".join(alert.mitre_attack_techniques),
                    "context_json": sanitize_csv_field(json.dumps(alert.context, ensure_ascii=True)),
                }
            )



def run_analysis(
    sample_path: str,
    duration_seconds: int,
    output_path: str,
    enable_yara: bool = False,
    yara_rules_path: str | None = None,
    alerts_csv_path: str | None = None,
    watch_paths: List[str] | None = None,
    require_vm: bool = True,
    debug_process: bool = False,
    dump_memory: bool = False,
    procdump_path: str = "procdump.exe",
    allowed_rules_dir: str | None = None,
    termination_timeout_seconds: int = 10,
    enable_job_object: bool = True,
    job_max_active_processes: int = 64,
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

    vm_detected, vm_evidence = check_vm_isolation()
    if require_vm and not vm_detected:
        raise RuntimeError(
            "VM isolation check failed. Refusing to run sample outside known VM artifacts. "
            f"Evidence: {vm_evidence}"
        )

    # Shared event stores and lock for thread-safe writes.
    file_events: List[FileEventRecord] = []
    process_events: List[ProcessEvent] = []
    network_events: List[NetworkEventRecord] = []
    security_alerts: List[SecurityAlertRecord] = []
    file_lock = threading.Lock()
    ttl_network_cache = TTLNetworkCache(ttl_seconds=30.0)

    # Set up filesystem observer for configured roots.
    default_watch_paths = [
        r"C:\Users",
        r"C:\Windows\Temp",
        r"C:\ProgramData",
        os.path.expandvars(r"%TEMP%"),
    ]
    resolved_watch_paths = default_watch_paths + (watch_paths or [])
    handler = UsersDirEventHandler(file_events, file_lock)
    observer = Observer()
    active_watch_paths: List[str] = []
    for root in resolved_watch_paths:
        expanded = os.path.abspath(os.path.expandvars(root))
        if os.path.isdir(expanded):
            observer.schedule(handler, path=expanded, recursive=True)
            active_watch_paths.append(expanded)

    # Start observer before launching sample to avoid missing early events.
    observer.start()

    # Launch sample with strict assign-before-execute containment when possible.
    if os.name == "nt" and enable_job_object:
        sample_proc: Any = launch_windows_process_suspended(sample_path, debug_process)
    else:
        creationflags = 0
        if os.name == "nt":
            creationflags |= CREATE_NEW_PROCESS_GROUP
            if debug_process:
                creationflags |= DEBUG_PROCESS
        sample_proc = subprocess.Popen(
            [sample_path],
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    job_handle: int | None = None
    if enable_job_object:
        proc_handle = int(getattr(sample_proc, "process_handle", 0) or getattr(sample_proc, "_handle", 0))
        if proc_handle:
            job_handle, job_object_status = create_and_assign_job_object(
                process_handle=proc_handle,
                max_active_processes=job_max_active_processes,
            )
            if job_handle is None:
                terminate_process_tree(sample_proc.pid, termination_timeout_seconds)
                raise RuntimeError(f"Job Object containment failed: {job_object_status.get('note', 'unknown error')}")
        else:
            job_object_status = {
                "method": "windows_job_object",
                "status": "unavailable",
                "note": "Process handle unavailable for Job Object assignment.",
            }
    else:
        job_object_status = {
            "method": "windows_job_object",
            "status": "disabled",
            "note": "Job Object containment disabled by CLI option.",
        }

    # Resume only after successful Job Object assignment (Windows strict path).
    if isinstance(sample_proc, WindowsProcessHandle):
        resume_windows_process(sample_proc)

    process_monitor = ProcessTreeMonitor(root_pid=sample_proc.pid)

    # Also log the root process itself as the initial execution IOC.
    try:
        root_ps = psutil.Process(sample_proc.pid)
        root_exe = safe_process_exe(root_ps)
        root_event = ProcessEvent(
            timestamp_utc=utc_now_iso(),
            pid=sample_proc.pid,
            ppid=safe_ppid(root_ps),
            name=safe_process_name(root_ps),
            cmdline=safe_process_cmdline(root_ps),
            exe_path=root_exe,
            sha256=process_monitor._sha256_for_exe(root_exe),
        )
        root_event.risk_score = calculate_process_risk_score(root_event)
        process_events.append(root_event)
        security_alerts.extend(build_process_alerts(root_event))
        process_monitor.seen_logged_pids.add(sample_proc.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    
    # Capture initial screenshot for visual baseline
    output_dir = os.path.dirname(output_path) or "."
    initial_screenshot_status = capture_desktop_screenshot(output_dir, prefix="screenshot_initial")

    # Reduced polling interval (0.2s instead of 1.0s) catches more short-lived processes
    poll_interval_seconds = 0.2
    end_time = time.time() + duration_seconds

    try:
        screenshot_interval = 30.0  # Capture screenshot every 30 seconds
        last_screenshot_time = time.time()
        
        while time.time() < end_time:
            # Gather newly discovered child/descendant processes.
            new_proc_events = process_monitor.collect_new_process_events()
            process_events.extend(new_proc_events)
            for event in new_proc_events:
                security_alerts.extend(build_process_alerts(event))

            # Gather network activity for tracked process tree members using TTL cache.
            new_network_events = collect_network_events_for_tracked_pids(
                process_monitor.tracked_tree_pids,
                ttl_network_cache,
            )
            network_events.extend(new_network_events)
            for event in new_network_events:
                security_alerts.extend(build_network_alerts(event))

            with file_lock:
                recent_file_events = file_events[-25:]
            for event in recent_file_events:
                security_alerts.extend(build_file_alerts(event))
            
            # Periodically capture screenshots for visual forensics
            current_time = time.time()
            if current_time - last_screenshot_time >= screenshot_interval:
                capture_desktop_screenshot(output_dir, prefix=f"screenshot_t{int(current_time - end_time + duration_seconds)}")
                last_screenshot_time = current_time

            time.sleep(poll_interval_seconds)
    finally:
        # Stop filesystem watcher first.
        observer.stop()
        observer.join(timeout=10)

        # Capture final screenshot
        final_screenshot_status = capture_desktop_screenshot(output_dir, prefix="screenshot_final")

        memory_dump_status = maybe_dump_process_memory(
            pid=sample_proc.pid,
            output_dir=output_dir,
            enabled=dump_memory,
            procdump_path=procdump_path,
        )

        # Best effort termination of root sample process if still running.
        if sample_proc.poll() is None:
            terminate_process_tree(sample_proc.pid, termination_timeout_seconds)
        close_job_object(job_handle)
        if isinstance(sample_proc, WindowsProcessHandle):
            sample_proc.close_handles()

    analysis_end_dt = datetime.now(timezone.utc)
    analysis_end = analysis_end_dt.isoformat()

    # Collect tracked process executables for registry correlation
    tracked_process_exes: Set[str] = {e.exe_path for e in process_events if e.exe_path}
    
    # Sysmon-assisted registry collection from Windows Event Log, filtered by process tree.
    registry_events, registry_collection_status = collect_sysmon_registry_events(
        analysis_start_dt,
        analysis_end_dt,
        tracked_process_exes=tracked_process_exes or None,
    )
    api_events, api_collection_status = collect_sysmon_api_events(
        analysis_start_dt,
        analysis_end_dt,
    )
    
    # Detect potential C2 beaconing patterns
    c2_beaconing = detect_c2_beaconing(network_events)

    yara_matches: List[YaraMatchRecord] = []
    if enable_yara:
        allowed_dir = os.path.abspath(allowed_rules_dir or os.path.dirname(__file__))
        rules_path = validate_rules_path(yara_rules_path or "yara_rules.yar", allowed_dir)
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
            "sysmon_api_events": [asdict(evt) for evt in api_events],
            "security_alerts": [asdict(evt) for evt in deduped_alerts],
            "yara_matches": [asdict(evt) for evt in yara_matches],
            "c2_beaconing_analysis": c2_beaconing,
        },
        "summary": {
            "process_event_count": len(process_events),
            "file_event_count": len(file_events),
            "network_event_count": len(network_events),
            "dns_event_count": len([evt for evt in network_events if evt.is_dns_related]),
            "registry_event_count": len(registry_events),
            "sysmon_api_event_count": len(api_events),
            "security_alert_count": len(deduped_alerts),
            "yara_match_count": len(yara_matches),
            "c2_beaconing_confidence": c2_beaconing.get("confidence_score", 0.0),
            "avg_process_risk_score": (sum(e.risk_score for e in process_events) / len(process_events)) if process_events else 0.0,
            "avg_network_risk_score": (sum(e.risk_score for e in network_events) / len(network_events)) if network_events else 0.0,
            "high_entropy_files": len([e for e in file_events if e.entropy and e.entropy > 7.0]),
            "notes": [
                "Process tracking polling interval reduced to 0.2s (improved short-lived process detection).",
                "Network connections use TTL-based deduplication (30s) to detect beaconing patterns.",
                "Filesystem monitoring uses configurable watcher roots with entropy analysis on dropped files.",
                "Registry tracking filtered to correlate with tracked process tree.",
                "C2 beaconing detection analyzes DNS frequency and connection persistence patterns.",
                "File entropy calculated to flag encrypted/packed payloads.",
                "Risk scores assigned to all IOC types (process/file/network/registry).",
                "Screenshots captured at initial, periodic (30s), and final analysis stages.",
                "Security alerts are heuristic signals and should be triaged with analyst review.",
            ],
        },
        "collection_status": {
            "registry": registry_collection_status,
            "sysmon_api_events": api_collection_status,
            "yara": yara_collection_status,
            "memory_dump": memory_dump_status,
            "screenshots": {
                "initial": initial_screenshot_status,
                "final": final_screenshot_status,
            },
            "vm_isolation_check": vm_evidence,
            "job_object": job_object_status,
        },
        "runtime_controls": {
            "vm_required": require_vm,
            "vm_detected": vm_detected,
            "debug_process_flag_enabled": debug_process,
            "watch_paths": active_watch_paths,
            "termination_timeout_seconds": termination_timeout_seconds,
            "job_object_enabled": enable_job_object,
            "job_active_process_limit": max(1, int(job_max_active_processes)),
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
    parser.add_argument(
        "--watch-path",
        action="append",
        default=[],
        help="Additional directory path to monitor (can be passed multiple times).",
    )
    parser.add_argument(
        "--allow-host",
        action="store_true",
        help="Allow execution even when VM artifacts are not detected.",
    )
    parser.add_argument(
        "--debug-process",
        action="store_true",
        help="Launch sample with DEBUG_PROCESS flag for improved process telemetry control.",
    )
    parser.add_argument(
        "--dump-memory",
        action="store_true",
        help="Capture sample memory dump with ProcDump before termination.",
    )
    parser.add_argument(
        "--procdump-path",
        default="procdump.exe",
        help="Path to ProcDump executable (default: procdump.exe).",
    )
    parser.add_argument(
        "--allowed-rules-dir",
        default=os.path.dirname(__file__),
        help="Allowed root directory for YARA rule files (default: script directory).",
    )
    parser.add_argument(
        "--termination-timeout",
        type=int,
        default=10,
        help="Seconds to wait for process tree shutdown before forced kill (default: 10).",
    )
    parser.add_argument(
        "--disable-job-object",
        action="store_true",
        help="Disable Windows Job Object containment (enabled by default).",
    )
    parser.add_argument(
        "--job-max-active-processes",
        type=int,
        default=64,
        help="Max active processes allowed inside the Job Object (default: 64).",
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
            watch_paths=args.watch_path,
            require_vm=not args.allow_host,
            debug_process=args.debug_process,
            dump_memory=args.dump_memory,
            procdump_path=args.procdump_path,
            allowed_rules_dir=os.path.abspath(args.allowed_rules_dir),
            termination_timeout_seconds=max(1, int(args.termination_timeout)),
            enable_job_object=not args.disable_job_object,
            job_max_active_processes=max(1, int(args.job_max_active_processes)),
        )

        print(f"[+] Analysis complete. JSON IOC report written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"[!] Analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

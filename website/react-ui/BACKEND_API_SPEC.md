"""
Flask Backend API Endpoints for SOC Dashboard
This file documents the required endpoints for full platform functionality.

Current Base URL: http://127.0.0.1:5000
"""

# ===== EXISTING ENDPOINTS (Already Implemented) =====
"""
POST /api/ioc-reports/import
POST /api/event-logs/analyze
POST /api/dns-simulator/events
POST /api/scan
POST /login
GET /api/history/scans
GET /api/history/threat-feed
GET /api/history/event-logs
GET /api/history/dns-simulator
GET /api/reports/latest
GET /api/threat-feed
"""

# ===== NEW ENDPOINTS REQUIRED (Phase 2) =====

# ========== YARA SCANNING ==========
"""
POST /api/yara/scan
Request Body:
{
  "events": [
    {
      "id": "event-1",
      "domain": "malicious.com",
      "source_ip": "192.168.1.1",
      "timestamp": "2024-01-15T10:30:00Z",
      "outcome": "blocked",
      "resolved_ip": "203.0.113.45"
    }
  ],
  "source": "ui-yara-scanner"
}

Response (YaraScanResponse):
{
  "status": "success",
  "scan_id": "scan-001-2024-01-15",
  "matches": [
    {
      "rule_name": "Suspicious_PowerShell_EncodedCommand",
      "severity": "high",
      "matched_strings": ["powershell.exe", "base64"],
      "affected_events": 3
    }
  ],
  "total_matches": 5
}
"""

# ========== ADMIN STATISTICS ==========
"""
GET /api/admin/stats
No query parameters required.

Response (AdminStatsResponse):
{
  "timestamp": "2024-01-15T15:45:30Z",
  "uptime_hours": 72.5,
  "cpu_usage_percent": 34.2,
  "memory_usage_percent": 52.8,
  "db_size_mb": 245.8,
  "total_ioc_reports": 42,
  "total_scans": 156,
  "total_event_logs": 1847,
  "total_dns_events": 3421,
  "threat_feeds_synced": 5,
  "api_requests_today": 2340
}

Health Status Calculation:
- CRITICAL: CPU > 85% OR Memory > 85% OR DB > 1000MB
- WARNING: CPU > 70% OR Memory > 70% OR DB > 500MB
- HEALTHY: Otherwise
"""

# ========== THREAT FEED SYNCING ==========
"""
POST /api/threat-feeds/sync
Request Body:
{
  "feed_sources": [
    "alienvault-otx",
    "abuse-urlhaus",
    "sans-isc",
    "greynoise",
    "emergingthreats"
  ]
}

Response (ThreatFeedSyncResponse):
{
  "status": "success",
  "feeds_synced": 5,
  "new_indicators": 234,
  "created_at_utc": "2024-01-15T16:20:15Z"
}

Implementation Notes:
- Should call real APIs for enabled feeds
- Deduplicate indicators across sources
- Aggregate confidence scores
- Store in SQLite with timestamps
- Rate limit to 5 syncs per hour per feed
"""

# ========== THREAT INDICATORS RETRIEVAL ==========
"""
GET /api/threat-indicators?severity=critical&limit=50
Query Parameters:
- severity (optional): "critical", "high", "medium", "low" or omit for all
- limit (optional): Max number of indicators to return (default: 100)

Response (HistoryResponse):
{
  "fetched_at_utc": "2024-01-15T16:30:00Z",
  "count": 45,
  "items": [
    {
      "id": "ind-001",
      "type": "c2_domain",
      "value": "command.malicious-actors.ru",
      "severity": "critical",
      "source": "AlienVault OTX",
      "confidence": 98,
      "added_at": "2024-01-15T10:00:00Z",
      "last_seen": "2024-01-15T15:30:00Z"
    },
    ...
  ]
}
"""

# ========== DETECTION RULES - CREATE ==========
"""
POST /api/detection-rules
Request Body (DetectionRule):
{
  "id": "rule-new-12345",
  "name": "Excessive Failed Login Attempts",
  "description": "Detects brute force attempts with 10+ failures in 5 minutes",
  "enabled": true,
  "severity": "high",
  "conditions": [
    {
      "field": "event_type",
      "operator": "equals",
      "value": "AUTH_FAILED"
    },
    {
      "field": "count",
      "operator": "greater_than",
      "value": "10"
    }
  ],
  "actions": ["alert", "log", "block_ip"],
  "created_at": "2024-01-15T16:00:00Z",
  "hit_count": 0
}

Response (DetectionRuleResponse):
{
  "status": "success",
  "rule_id": "rule-new-12345",
  "created_at_utc": "2024-01-15T16:00:00Z",
  "message": "Rule created successfully"
}
"""

# ========== DETECTION RULES - LIST ==========
"""
GET /api/detection-rules
No parameters required.

Response (DetectionRuleListResponse):
{
  "rules": [
    {
      "id": "rule-001",
      "name": "Excessive Failed Login Attempts",
      "description": "Detects brute force attempts with 10+ failures in 5 minutes",
      "severity": "high",
      "enabled": true,
      "hit_count": 47
    },
    ...
  ],
  "total_count": 25
}
"""

# ========== DETECTION RULES - UPDATE ==========
"""
PATCH /api/detection-rules/{rule_id}
Request Body:
{
  "enabled": false
}

Response (DetectionRuleResponse):
{
  "status": "success",
  "rule_id": "rule-001",
  "created_at_utc": "2024-01-15T16:00:00Z",
  "message": "Rule updated successfully"
}
"""

# ========== DETECTION RULES - DELETE ==========
"""
DELETE /api/detection-rules/{rule_id}
No request body.

Response (DetectionRuleResponse):
{
  "status": "success",
  "rule_id": "rule-001",
  "created_at_utc": "2024-01-15T16:00:00Z",
  "message": "Rule deleted successfully"
}
"""

# ========== REPORT GENERATION ==========
"""
POST /api/reports/generate
Request Body (ReportConfig):
{
  "report_type": "executive|technical|threat_intelligence|compliance",
  "format": "pdf|html|csv|json",
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-01-15T23:59:59Z",
  "include_metrics": true,
  "include_findings": true,
  "include_recommendations": true,
  "include_threat_intel": true,
  "sign_report": true,
  "signature_name": "SOC Manager"
}

Response:
{
  "status": "success",
  "report_id": "rpt-001-2024-01-15",
  "download_url": "/api/reports/download/rpt-001-2024-01-15.pdf",
  "generated_at_utc": "2024-01-15T17:00:00Z",
  "file_size_bytes": 256000,
  "format": "pdf"
}

Implementation Notes:
- Generate reports with templated sections
- Support multiple export formats
- Include statistics, findings, recommendations
- Allow time-range filtering
- Optional digital signatures for compliance
"""

# ========== BACKEND DATABASE SCHEMA UPDATES ==========
"""
Required SQLite Tables:

1. detection_rules
   - id (PRIMARY KEY)
   - name (TEXT)
   - description (TEXT)
   - enabled (BOOLEAN)
   - severity (ENUM: critical/high/medium/low)
   - conditions (JSON)
   - actions (JSON)
   - created_at (TIMESTAMP)
   - updated_at (TIMESTAMP)
   - hit_count (INTEGER)

2. threat_indicators
   - id (PRIMARY KEY)
   - type (ENUM: malware_hash/c2_domain/malicious_ip/phishing_url/suspicious_file)
   - value (TEXT, UNIQUE)
   - severity (ENUM: critical/high/medium/low)
   - source (TEXT) -- which feed it came from
   - confidence (FLOAT 0-100)
   - added_at (TIMESTAMP)
   - last_seen (TIMESTAMP)
   - feed_id (FOREIGN KEY to threat_feeds)

3. threat_feeds
   - id (PRIMARY KEY)
   - name (TEXT)
   - url (TEXT)
   - enabled (BOOLEAN)
   - last_synced (TIMESTAMP)
   - indicator_count (INTEGER)
   - update_interval_hours (INTEGER)
   - format (ENUM: json/csv/txt)

4. admin_stats (or system_metrics)
   - id (PRIMARY KEY)
   - timestamp (TIMESTAMP)
   - uptime_hours (FLOAT)
   - cpu_usage_percent (FLOAT)
   - memory_usage_percent (FLOAT)
   - db_size_mb (FLOAT)
   - total_ioc_reports (INTEGER)
   - total_scans (INTEGER)
   - total_event_logs (INTEGER)
   - total_dns_events (INTEGER)
   - threat_feeds_synced (INTEGER)
   - api_requests_today (INTEGER)
"""

# ========== IMPLEMENTATION CHECKLIST ==========
"""
PRIORITY 1 - Core Functionality:
☐ POST /api/yara/scan - Malware signature scanning
☐ GET /api/admin/stats - System metrics and health
☐ POST /api/threat-feeds/sync - Feed synchronization
☐ GET /api/threat-indicators - Indicator retrieval

PRIORITY 2 - Detection Rules Persistence:
☐ POST /api/detection-rules - Create rules
☐ GET /api/detection-rules - List all rules
☐ PATCH /api/detection-rules/{id} - Enable/disable
☐ DELETE /api/detection-rules/{id} - Delete rules

PRIORITY 3 - Advanced Features:
☐ POST /api/reports/generate - Report generation
☐ Database schema migrations for new tables
☐ Real threat feed API integrations
☐ Rule execution/enforcement engine

TESTING:
☐ All endpoints return correct response types
☐ Error handling with proper status codes
☐ Authentication/authorization checks
☐ Rate limiting on feed sync endpoints
☐ Database transaction handling
☐ Concurrent request handling
"""

export type DetectionRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: "critical" | "high" | "medium" | "low";
  conditions: Array<{
    field: string;
    operator: "equals" | "contains" | "greater_than" | "less_than" | "regex";
    value: string;
  }>;
  actions: string[];
  created_at: string;
  hit_count: number;
};

export type EnvironmentTemplate = {
  id: string;
  name: string;
  description: string;
  icon: string;
  rules: DetectionRule[];
};

// Small Business - Focused on common threats and compliance
const SMALL_BUSINESS_RULES: DetectionRule[] = [
  {
    id: "sb-001",
    name: "Brute Force Login Attack",
    description: "Detects 5+ failed login attempts in 5 minutes",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "event_type", operator: "equals", value: "AUTH_FAILED" },
      { field: "count", operator: "greater_than", value: "5" }
    ],
    actions: ["alert", "block_ip", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "sb-002",
    name: "Suspicious Outbound Traffic",
    description: "Detects unusual data exfiltration patterns",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "data_transfer_mb", operator: "greater_than", value: "500" },
      { field: "destination", operator: "regex", value: "^(?!internal|trusted)" }
    ],
    actions: ["alert", "log", "investigate"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "sb-003",
    name: "Ransomware File Behavior",
    description: "Detects bulk file encryption/deletion patterns",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "file_operations", operator: "contains", value: "encrypt" },
      { field: "file_count", operator: "greater_than", value: "100" }
    ],
    actions: ["alert", "isolate_host", "quarantine"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "sb-004",
    name: "USB Device Connection",
    description: "Alerts on unauthorized USB device connections",
    enabled: true,
    severity: "medium",
    conditions: [
      { field: "event_type", operator: "equals", value: "USB_CONNECT" },
      { field: "device_approved", operator: "equals", value: "false" }
    ],
    actions: ["alert", "log", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

// Enterprise - Complex attack detection and correlation
const ENTERPRISE_RULES: DetectionRule[] = [
  {
    id: "ent-001",
    name: "Lateral Movement Detection",
    description: "Detects suspicious lateral movement patterns",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "event_type", operator: "equals", value: "NETWORK_ACCESS" },
      { field: "authentication_method", operator: "equals", value: "pass_the_hash" }
    ],
    actions: ["alert", "block_domain", "investigate", "isolate_host"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "ent-002",
    name: "Privilege Escalation Attempt",
    description: "Detects attempts to escalate user privileges",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "message", operator: "regex", value: "sudo|admin|elevated|privilege" },
      { field: "source_privilege_level", operator: "equals", value: "user" },
      { field: "target_privilege_level", operator: "equals", value: "admin" }
    ],
    actions: ["alert", "block_ip", "quarantine", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "ent-003",
    name: "Advanced Persistence Threat Detection",
    description: "Detects APT indicators: process injection, DLL loading, registry mods",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "process_injection_detected", operator: "equals", value: "true" },
      { field: "unsigned_driver_loaded", operator: "equals", value: "true" }
    ],
    actions: ["alert", "isolate_host", "investigate", "quarantine"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "ent-004",
    name: "Command & Control Communication",
    description: "Detects communication to known C2 servers",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "destination_ip", operator: "regex", value: "c2_indicator|malware_domain" },
      { field: "protocol", operator: "regex", value: "dns|http|https" }
    ],
    actions: ["alert", "block_domain", "block_ip", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "ent-005",
    name: "Credential Dumping Detection",
    description: "Detects LSASS memory access and credential theft attempts",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "process", operator: "contains", value: "lsass" },
      { field: "memory_access", operator: "equals", value: "read" }
    ],
    actions: ["alert", "block_process", "quarantine", "investigate"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

// Financial Services (PCI-DSS) - Compliance-focused
const FINANCIAL_SERVICES_RULES: DetectionRule[] = [
  {
    id: "fin-001",
    name: "Cardholder Data Access Outside Authorized Hours",
    description: "PCI-DSS: Alerts on CHD access outside business hours",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "data_type", operator: "equals", value: "CARDHOLDER_DATA" },
      { field: "access_time", operator: "regex", value: "22:00-06:00" }
    ],
    actions: ["alert", "log", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "fin-002",
    name: "Unauthorized Database Query",
    description: "PCI-DSS: Detects queries to cardholder database from unauthorized users",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "database", operator: "contains", value: "cardholder" },
      { field: "user_authorized_for_db", operator: "equals", value: "false" }
    ],
    actions: ["alert", "block_access", "quarantine", "audit_log"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "fin-003",
    name: "Failed Encryption Detection",
    description: "HIPAA/PCI: Alerts on unencrypted data transmission",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "data_type", operator: "regex", value: "PII|CARDHOLDER|SENSITIVE" },
      { field: "encryption", operator: "equals", value: "false" }
    ],
    actions: ["alert", "block_transmission", "log", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "fin-004",
    name: "Mass Data Export Detection",
    description: "Detects bulk export of financial/customer data",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "export_size_mb", operator: "greater_than", value: "100" },
      { field: "data_sensitivity", operator: "equals", value: "high" }
    ],
    actions: ["alert", "block_access", "investigate", "notify_compliance"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

// Healthcare (HIPAA) - Patient data and audit focus
const HEALTHCARE_RULES: DetectionRule[] = [
  {
    id: "health-001",
    name: "Unauthorized PHI Access",
    description: "HIPAA: Detects access to Protected Health Information by unauthorized users",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "data_type", operator: "equals", value: "PHI" },
      { field: "user_clearance", operator: "equals", value: "false" }
    ],
    actions: ["alert", "block_access", "audit_log", "notify_compliance"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "health-002",
    name: "Large Patient Record Download",
    description: "Detects unusual bulk PHI extraction",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "record_count", operator: "greater_than", value: "1000" },
      { field: "data_type", operator: "equals", value: "PHI" }
    ],
    actions: ["alert", "block_download", "investigate", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "health-003",
    name: "Unencrypted Data Transmission",
    description: "HIPAA: Alerts on unencrypted PHI transmission",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "data_type", operator: "equals", value: "PHI" },
      { field: "encryption", operator: "equals", value: "false" }
    ],
    actions: ["alert", "block_transmission", "log", "notify_hipaa_officer"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "health-004",
    name: "Audit Log Tampering",
    description: "Detects attempts to modify or delete audit logs",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "event_type", operator: "regex", value: "audit_delete|audit_modify" }
    ],
    actions: ["alert", "isolate_host", "investigate", "notify_compliance"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

// Manufacturing/OT (Operational Technology) - Industrial controls
const MANUFACTURING_RULES: DetectionRule[] = [
  {
    id: "mfg-001",
    name: "Unauthorized PLC Access",
    description: "Detects unauthorized access to programmable logic controllers",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "device_type", operator: "equals", value: "PLC" },
      { field: "access_authorized", operator: "equals", value: "false" }
    ],
    actions: ["alert", "block_access", "isolate_device", "notify_supervisor"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "mfg-002",
    name: "Process Parameter Modification",
    description: "Detects anomalous changes to critical process parameters",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "parameter_type", operator: "regex", value: "pressure|temperature|speed" },
      { field: "change_magnitude_percent", operator: "greater_than", value: "20" }
    ],
    actions: ["alert", "revert_change", "investigate", "notify_engineering"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "mfg-003",
    name: "SCADA Communication Anomaly",
    description: "Detects unusual SCADA protocol patterns",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "protocol", operator: "equals", value: "MODBUS|PROFIBUS" },
      { field: "packet_anomaly_score", operator: "greater_than", value: "8" }
    ],
    actions: ["alert", "log", "investigate", "notify_soc"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "mfg-004",
    name: "Safety System Bypass",
    description: "Detects attempts to disable safety interlocks",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "safety_system", operator: "regex", value: "emergency_stop|interlock|governor" },
      { field: "status_change", operator: "equals", value: "disabled" }
    ],
    actions: ["alert", "emergency_shutdown", "isolate_equipment", "notify_safety"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

// SaaS/Cloud-Native - Multi-tenant and API-focused
const SAAS_CLOUD_RULES: DetectionRule[] = [
  {
    id: "saas-001",
    name: "API Key Compromise",
    description: "Detects suspicious API key usage from multiple IPs",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "api_key_unique_ips", operator: "greater_than", value: "5" },
      { field: "time_window_minutes", operator: "equals", value: "60" }
    ],
    actions: ["alert", "revoke_api_key", "investigate", "notify_customer"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "saas-002",
    name: "Cross-Tenant Data Access",
    description: "Detects potential multi-tenant isolation bypass",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "tenant_id", operator: "regex", value: "unauthorized_cross_tenant" },
      { field: "data_accessed", operator: "equals", value: "other_tenant_data" }
    ],
    actions: ["alert", "block_session", "isolate_tenant", "incident_response"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "saas-003",
    name: "DDoS Attack Detection",
    description: "Detects distributed denial of service patterns",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "requests_per_second", operator: "greater_than", value: "10000" },
      { field: "source_ips_unique", operator: "greater_than", value: "100" }
    ],
    actions: ["alert", "rate_limit", "block_sources", "notify_operations"],
    created_at: new Date().toISOString(),
    hit_count: 0
  },
  {
    id: "saas-004",
    name: "Kubernetes RBAC Violation",
    description: "Detects unauthorized Kubernetes API access",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "kubernetes_api_call", operator: "equals", value: "true" },
      { field: "rbac_allowed", operator: "equals", value: "false" }
    ],
    actions: ["alert", "audit_log", "investigate", "notify_devops"],
    created_at: new Date().toISOString(),
    hit_count: 0
  }
];

export const ENVIRONMENT_TEMPLATES: EnvironmentTemplate[] = [
  {
    id: "small-business",
    name: "Small Business",
    description: "Optimized for small organizations with basic security needs",
    icon: "🏢",
    rules: SMALL_BUSINESS_RULES
  },
  {
    id: "enterprise",
    name: "Enterprise Infrastructure",
    description: "Comprehensive detection for large organizations",
    icon: "🏛️",
    rules: ENTERPRISE_RULES
  },
  {
    id: "financial",
    name: "Financial Services (PCI-DSS)",
    description: "Compliance-focused for financial institutions",
    icon: "💳",
    rules: FINANCIAL_SERVICES_RULES
  },
  {
    id: "healthcare",
    name: "Healthcare (HIPAA)",
    description: "Patient data protection and compliance",
    icon: "🏥",
    rules: HEALTHCARE_RULES
  },
  {
    id: "manufacturing",
    name: "Manufacturing/OT",
    description: "Industrial control systems and operational technology",
    icon: "🏭",
    rules: MANUFACTURING_RULES
  },
  {
    id: "saas",
    name: "SaaS/Cloud-Native",
    description: "Multi-tenant and containerized environments",
    icon: "☁️",
    rules: SAAS_CLOUD_RULES
  }
];

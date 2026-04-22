export type DashboardMetric = {
  label: string;
  value: string;
  trend: string;
};

export type ToolCard = {
  title: string;
  description: string;
  badge: string;
};

export const dashboardMetrics: DashboardMetric[] = [
  { label: "Live Threat Indicators", value: "128", trend: "+12%" },
  { label: "Flagged Connections", value: "37", trend: "+4%" },
  { label: "IOC Uploads (24h)", value: "19", trend: "+22%" },
  { label: "Scan Requests Blocked", value: "54", trend: "+31%" }
];

export const toolCards: ToolCard[] = [
  {
    title: "IOC Upload",
    description: "Import sandbox ioc_report.json and map process/network indicators.",
    badge: "Core"
  },
  {
    title: "Threat Feed",
    description: "Pull live malicious IP intelligence and track source confidence.",
    badge: "Intel"
  },
  {
    title: "Entropy Lab",
    description: "Explain password cracking windows using real-time scoring.",
    badge: "Education"
  },
  {
    title: "Hash Generator",
    description: "Visualize MD5, SHA1, SHA256 one-way transformations.",
    badge: "Crypto"
  }
];
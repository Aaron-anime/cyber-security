import ToolLibraryGrid from "../components/ToolLibraryGrid";

const toolCards = [
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

function ToolLibraryPage() {
  return <ToolLibraryGrid tools={toolCards} />;
}

export default ToolLibraryPage;
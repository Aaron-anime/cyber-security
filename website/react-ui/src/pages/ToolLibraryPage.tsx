import ToolLibraryGrid from "../components/ToolLibraryGrid";
import { toolCards } from "../data/controlCenterContent";
import PasswordEntropyLab from "../components/PasswordEntropyLab";
import CryptographyHashGenerator from "../components/CryptographyHashGenerator";

function ToolLibraryPage() {
  return (
    <>
      <section className="library-launchpad panel-reveal glass-panel">
        <div>
          <p className="eyebrow">Library Launcher</p>
          <h2>Interactive cyber security modules</h2>
          <p className="muted-text">
            Jump straight into the two hands-on labs, or browse the module cards for a broader
            overview of the library.
          </p>
        </div>

        <div className="launcher-actions">
          <a className="tool-action launcher-link" href="#entropy-lab">
            Open Password Entropy Lab
          </a>
          <a className="tool-action launcher-link" href="#hash-generator">
            Open Hash Generator
          </a>
        </div>
      </section>

      <ToolLibraryGrid tools={toolCards} />
      <div className="library-workbench">
        <div id="entropy-lab">
          <PasswordEntropyLab />
        </div>
        <div id="hash-generator">
          <CryptographyHashGenerator />
        </div>
      </div>
    </>
  );
}

export default ToolLibraryPage;
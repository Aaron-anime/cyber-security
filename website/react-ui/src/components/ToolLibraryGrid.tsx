import { Link } from "react-router-dom";

type ToolCard = {
  title: string;
  description: string;
  badge: string;
  route?: string;
};

type ToolLibraryGridProps = {
  tools: ToolCard[];
};

function ToolLibraryGrid({ tools }: ToolLibraryGridProps) {
  return (
    <section className="tool-library panel-reveal">
      <header className="tool-library-header">
        <p className="eyebrow">Tool Library</p>
        <h3>Componentized Security Modules</h3>
      </header>

      <div className="tool-grid">
        {tools.map((tool) => (
          <article key={tool.title} className="tool-card panel-reveal">
            <span className="tool-badge">{tool.badge}</span>
            <h4>{tool.title}</h4>
            <p>{tool.description}</p>
            {tool.route ? (
              <Link to={tool.route} className="tool-action launcher-link">
                Open Module
              </Link>
            ) : (
              <button type="button" className="tool-action" aria-disabled="true">
                Open Module
              </button>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

export default ToolLibraryGrid;
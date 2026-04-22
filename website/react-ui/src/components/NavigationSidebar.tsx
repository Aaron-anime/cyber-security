import { NavLink } from "react-router-dom";

const links = [
  { label: "Main Dashboard", to: "/dashboard" },
  { label: "Tool Library", to: "/tools" },
  { label: "Threat Intelligence", to: "/threat-intelligence" },
  { label: "IOC Reports", to: "/ioc-reports" },
  { label: "IOC Dashboard", to: "/ioc-dashboard" },
  { label: "Scanner", to: "/scanner" },
  { label: "Login", to: "/login" },
  { label: "History", to: "/history" }
];

function NavigationSidebar() {
  return (
    <aside className="nav-sidebar panel-reveal">
      <div className="brand-block">
        <p className="brand-kicker">Defense Console</p>
        <h1>Cyber Shield Lab</h1>
      </div>

      <nav aria-label="Primary">
        <ul className="nav-list">
          {links.map((link) => (
            <li key={link.label}>
              <NavLink
                to={link.to}
                className={({ isActive }) =>
                  isActive ? "nav-link-btn nav-link-btn-active" : "nav-link-btn"
                }
              >
                {link.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
}

export default NavigationSidebar;
import React from "react";
import "../css/sidebar.css"; 

const NAV_ITEMS = [
  { key: "overview", label: "Overview", icon: "home" },
  { key: "threats", label: "Threats", icon: "bug" },
  { key: "log", label: "Log Analysis", icon: "file" },
  { key: "pe", label: "PE File Scanner", icon: "scan" },
  { key: "model", label: "Model Analytics", icon: "chart" },
  { key: "settings", label: "Settings", icon: "settings" },
  { key: "support", label: "Support", icon: "help" },
];

const Icon = ({ name, className = "" }) => {
  const baseProps = {
    viewBox: "0 0 24 24",
    fill: "none",
    strokeWidth: 1.8,
    strokeLinecap: "round",
    strokeLinejoin: "round",
  };

  const cls = `cg-sidebar__icon-svg ${className}`.trim();

  switch (name) {
    case "home":
      return (
        <svg {...baseProps} className={cls}>
          <path d="M3 11.5 12 4l9 7.5" />
          <path d="M5 10.5V20h14v-9.5" />
          <path d="M9.5 20v-6h5v6" />
        </svg>
      );

    case "bug":
      return (
        <svg {...baseProps} className={cls}>
          <path d="M9 9a3 3 0 0 1 6 0v2a3 3 0 0 1-6 0V9Z" />
          <path d="M8 13h8" />
          <path d="M6 8l2 1" />
          <path d="M18 8l-2 1" />
          <path d="M6 16l2-1" />
          <path d="M18 16l-2-1" />
          <path d="M12 5v2" />
          <path d="M10 19a4 4 0 0 0 4 0" />
        </svg>
      );

    case "file":
      return (
        <svg {...baseProps} className={cls}>
          <path d="M7 3h7l5 5v13H7z" />
          <path d="M14 3v5h5" />
          <path d="M10 12h6" />
          <path d="M10 16h6" />
        </svg>
      );

    case "scan":
      return (
        <svg {...baseProps} className={cls}>
          <path d="M4 7V5a1 1 0 0 1 1-1h2" />
          <path d="M20 7V5a1 1 0 0 0-1-1h-2" />
          <path d="M4 17v2a1 1 0 0 0 1 1h2" />
          <path d="M20 17v2a1 1 0 0 1-1 1h-2" />
          <path d="M7 12h10" />
        </svg>
      );

    case "chart":
      return (
        <svg {...baseProps} className={cls}>
          <path d="M4 19V5" />
          <path d="M4 19h16" />
          <path d="M8 15l3-3 3 2 4-5" />
        </svg>
      );

    case "settings":
      return (
        <svg {...baseProps} className={cls}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 2v2" />
          <path d="M12 20v2" />
          <path d="M4.9 4.9l1.4 1.4" />
          <path d="M17.7 17.7l1.4 1.4" />
          <path d="M2 12h2" />
          <path d="M20 12h2" />
          <path d="M4.9 19.1l1.4-1.4" />
          <path d="M17.7 6.3l1.4-1.4" />
        </svg>
      );

    case "help":
      return (
        <svg {...baseProps} className={cls}>
          <circle cx="12" cy="12" r="9" />
          <path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 2-2.5 2-2.5 4" />
          <path d="M12 17h.01" />
        </svg>
      );

    default:
      return (
        <svg {...baseProps} className={cls}>
          <circle cx="12" cy="12" r="8" />
        </svg>
      );
  }
};

export default function Sidebar({
  activeKey = "model",
  onChange,
  items = NAV_ITEMS,
  className = "",
}) {
  return (
    <aside className={`cg-sidebar ${className}`.trim()}>
      <nav className="cg-sidebar__nav">
        {items.map((item) => {
          const active = item.key === activeKey;

          return (
            <button
              key={item.key}
              type="button"
              onClick={() => onChange?.(item.key)}
              aria-current={active ? "page" : undefined}
              className={`cg-sidebar__item ${active ? "is-active" : ""}`}
            >
              <span
                className={`cg-sidebar__icon ${
                  active ? "is-active" : ""
                }`}
              >
                <Icon name={item.icon} />
              </span>

              <span className="cg-sidebar__label">{item.label}</span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}

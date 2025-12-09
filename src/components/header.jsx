import React, { useMemo, useState, useEffect } from "react";
import "../css/header.css";

/**
 * CyberGuard Header (CSS version)
 * - Auto read logged user from localStorage/sessionStorage key: "cg_user"
 *
 * Props:
 *  - initialEnv: "demo" | "production"
 *  - onEnvChange?: (env) => void
 *  - onSearch?: (value) => void
 *  - placeholder?: string
 *  - user?: fallback user if storage empty
 */
export default function Header({
  initialEnv = "demo",
  onEnvChange,
  onSearch,
  placeholder = "Search past scans by filename, hash, or user...",
  user = { name: "Analyst", role: "Admin", avatarUrl: "" },
}) {
  const [env, setEnv] = useState(initialEnv);
  const [query, setQuery] = useState("");

  // ---- read user from storage ----
  const readStoredUser = () => {
    try {
      const rawLocal = localStorage.getItem("cg_user");
      if (rawLocal) return JSON.parse(rawLocal);

      const rawSession = sessionStorage.getItem("cg_user");
      if (rawSession) return JSON.parse(rawSession);
    } catch (_) {}
    return null;
  };

  const [storedUser, setStoredUser] = useState(() => readStoredUser());

  // update on mount + when other tabs change storage
  useEffect(() => {
    setStoredUser(readStoredUser());

    const handleStorage = (e) => {
      if (e.key === "cg_user") {
        setStoredUser(readStoredUser());
      }
    };

    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const effectiveUser = storedUser ?? user;

  const envLabel = useMemo(
    () => (env === "demo" ? "Demo" : "Production"),
    [env]
  );

  const handleEnv = (next) => {
    setEnv(next);
    onEnvChange?.(next);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSearch?.(query.trim());
  };

  return (
    <header className="cg-header">
      <div className="cg-header__bar">
        {/* LEFT: brand */}
        <div className="cg-header__brand">
          <span className="cg-header__brand-badge">
            <ShieldIcon className="cg-icon cg-icon--brand" />
          </span>
          <span className="cg-header__brand-title">CyberGuard Dashboard</span>
        </div>

        {/* CENTER: search */}
        <form onSubmit={handleSubmit} className="cg-header__search-form">
          <div className="cg-header__search-wrap">
            <span className="cg-header__search-icon">
              <SearchIcon className="cg-icon cg-icon--search" />
            </span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={placeholder}
              className="cg-header__search-input"
            />
          </div>
        </form>

        {/* RIGHT: env toggle + icons */}
        <div className="cg-header__right">
          {/* Segmented control */}
          <div className="cg-header__segmented">
            <button
              type="button"
              onClick={() => handleEnv("demo")}
              className={
                "cg-header__segmented-btn" +
                (env === "demo" ? " is-active" : "")
              }
            >
              Demo
            </button>
            <div className="cg-header__segmented-divider" />
            <button
              type="button"
              onClick={() => handleEnv("production")}
              className={
                "cg-header__segmented-btn" +
                (env === "production" ? " is-active" : "")
              }
            >
              Production
            </button>
          </div>

          {/* Status dot */}
          <span
            title={envLabel}
            className={
              "cg-header__status-dot " +
              (env === "demo"
                ? "cg-header__status-dot--demo"
                : "cg-header__status-dot--prod")
            }
          />

          {/* Notification */}
          <button
            type="button"
            className="cg-header__bell-btn"
            aria-label="Notifications"
          >
            <BellIcon className="cg-icon cg-icon--bell" />
            <span className="cg-header__bell-badge">2</span>
          </button>

          {/* User */}
          <div className="cg-header__user">
            <div className="cg-header__user-meta">
              <div className="cg-header__user-name">
                {effectiveUser?.name ?? "Analyst"}
              </div>
              <div className="cg-header__user-role">
                {effectiveUser?.role ?? "Admin"}
              </div>
            </div>

            <Avatar
              avatarUrl={effectiveUser?.avatarUrl}
              name={effectiveUser?.name}
            />
          </div>
        </div>
      </div>
    </header>
  );
}

/* ---------- Avatar ---------- */

function Avatar({ avatarUrl = "", name = "A" }) {
  if (avatarUrl) {
    return <img src={avatarUrl} alt={name} className="cg-avatar__img" />;
  }

  const letter = (name?.trim()?.[0] || "A").toUpperCase();

  return (
    <div className="cg-avatar">
      <span className="cg-avatar__initial">{letter}</span>
    </div>
  );
}

/* ---------- Icons (inline SVG) ---------- */

function ShieldIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3Z" />
      <path d="M9.5 12.2 11 13.7l3.8-3.8" />
    </svg>
  );
}

function SearchIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </svg>
  );
}

function BellIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M18 8a6 6 0 1 0-12 0c0 7-3 7-3 7h18s-3 0-3-7" />
      <path d="M9.5 19a2.5 2.5 0 0 0 5 0" />
    </svg>
  );
}

// src/layout/layout.jsx
import React, { useMemo } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import Header from "../components/header.jsx";
import Sidebar from "../components/sidebar.jsx";
import "../css/layout.css";

const KEY_TO_PATH = {
  overview: "/overview",
  threats: "/threats",

  log: "/log-analysis",
  pe: "/pe-scanner",
  model: "/model-analytics",
  settings: "/settings",
  support: "/support",
};

const PATH_TO_KEY = [
  { prefix: "/overview", key: "overview" },
  { prefix: "/threats", key: "threats" },

  { prefix: "/log-analysis", key: "log" },
  { prefix: "/pe-scanner", key: "pe" },
  { prefix: "/model-analytics", key: "model" },
  { prefix: "/settings", key: "settings" },
  { prefix: "/support", key: "support" },
];

const STORAGE_KEY = "cg_user";

function getStoredUser() {
  try {
    const ls = localStorage.getItem(STORAGE_KEY);
    if (ls) return JSON.parse(ls);

    const ss = sessionStorage.getItem(STORAGE_KEY);
    if (ss) return JSON.parse(ss);
  } catch (_) {}
  return null;
}

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();

  const activeKey = useMemo(() => {
    const path = location.pathname || "/";
    const found = PATH_TO_KEY.find((p) => path.startsWith(p.prefix));
    return found?.key || "overview";
  }, [location.pathname]);

  const handleSidebarChange = (key) => {
    const to = KEY_TO_PATH[key];
    if (to) navigate(to);
  };

  const user = useMemo(() => {
    return getStoredUser() || { name: "Analyst", role: "Admin" };
  }, [location.pathname]);

  return (
    <div className="cg-shell">
      <Header
        initialEnv="demo"
        onEnvChange={(e) => console.log("env:", e)}
        onSearch={(q) => console.log("search:", q)}
        user={user}
      />

      <div className="cg-shell__body">
        <Sidebar
          activeKey={activeKey}
          onChange={handleSidebarChange}
          className="cg-shell__sidebar"
        />

        <main className="cg-shell__content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

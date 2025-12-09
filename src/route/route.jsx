// src/route/route.jsx
import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import Layout from "../layout/layout.jsx";
import Login from "../client/Login.jsx";

import OverviewPage from "../pages/OverviewPage.jsx";
import ThreatsPage from "../pages/ThreatsPage.jsx";
import Threat from "../pages/Threat.jsx";

import FileScan from "../pages/FileScan.jsx";
import Log from "../pages/Log.jsx";
import Model from "../pages/Model.jsx";
import Setting from "../pages/Setting.jsx";
import Sp from "../pages/Sp.jsx";

export default function AppRoutes() {
  return (
    <Routes>
      {/* app open => login first */}
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<Login />} />

      {/* dashboard shell */}
      <Route element={<Layout />}>
        {/* default inside layout */}
        <Route index element={<Navigate to="/overview" replace />} />

        {/* main pages */}
        <Route path="/overview" element={<OverviewPage />} />

        {/* Threats list + detail */}
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/threats/:id" element={<Threat />} />

        {/* File scanning page  */}
        <Route path="/file-scan" element={<FileScan />} />
        <Route path="/pe-scanner" element={<FileScan />} />

        {/* Log analysis page  */}
        <Route path="/log-analysis" element={<Log />} />
        <Route path="/scan-history" element={<Log />} />

        {/* Model analytics */}
        <Route path="/model-analytics" element={<Model />} />

        {/* Settings */}
        <Route path="/settings" element={<Setting />} />

        {/* Support */}
        <Route path="/support" element={<Sp />} />
      </Route>

      {/* fallback */}
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}

const API_BASE = process.env.REACT_APP_API_BASE_URL || "";

export async function getThreats({ signal } = {}) {
  const res = await fetch(`${API_BASE}/api/threats`, { signal });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load threats");
  }

  return res.json();
}

export async function getThreatDetail(id, { signal } = {}) {
  if (!id) throw new Error("Missing threat id");

  const res = await fetch(
    `${API_BASE}/api/threats/${encodeURIComponent(id)}`,
    { signal }
  );

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load threat detail");
  }

  return res.json();
}

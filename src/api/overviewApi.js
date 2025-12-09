const API_BASE =
  process.env?.REACT_APP_API_BASE_URL ||
  process.env?.REACT_APP_API_BASE ||
  "";

const BASE = String(API_BASE || "").replace(/\/$/, "");

export async function getOverview({ signal } = {}) {
  const url = BASE ? `${BASE}/api/overview` : `/api/overview`;

  const res = await fetch(url, { signal });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load overview");
  }

  return res.json();
}

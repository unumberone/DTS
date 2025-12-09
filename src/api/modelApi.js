const API_BASE = process.env.REACT_APP_API_BASE_URL || "";

export async function getModelAnalytics(modelKey = "lstm", { signal } = {}) {
  const mk = encodeURIComponent(modelKey || "lstm");
  const res = await fetch(`${API_BASE}/api/models/${mk}/analytics`, { signal });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load model analytics");
  }

  return res.json();
}

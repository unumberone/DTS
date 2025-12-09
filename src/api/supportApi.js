const API_BASE = process.env.REACT_APP_API_BASE_URL || "";

async function safeJson(res) {
  const text = await res.text().catch(() => "");
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new Error(text || "Invalid JSON response");
  }
}

/**
 * GET /api/support/hub
 * return:
 * {
 *   announcements: [{ id, title, date, dateLabel, isNew }],
 *   tickets: [{ id, subject, status, updatedAt }],
 *   chat: { available: boolean }
 * }
 */
export async function getSupportHub({ signal } = {}) {
  const res = await fetch(`${API_BASE}/api/support/hub`, { signal });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Failed to load support hub");
  }
  return safeJson(res);
}

/**
 * GET /api/support/kb/search?q=
 * return: { items: [{ id, title, snippet, tags[] }] }
 */
export async function searchKnowledgeBase(q, { signal } = {}) {
  const query = encodeURIComponent(String(q || "").trim());
  const res = await fetch(`${API_BASE}/api/support/kb/search?q=${query}`, {
    signal,
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "KB search failed");
  }
  return safeJson(res);
}

/**
 * POST /api/support/tickets
 * body { category, subject, priority, description }
 * return: { ticket } or { tickets }
 */
export async function createTicket(payload, { signal } = {}) {
  const res = await fetch(`${API_BASE}/api/support/tickets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
    signal,
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Create ticket failed");
  }
  return safeJson(res);
}

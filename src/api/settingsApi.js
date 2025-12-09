const API_BASE = process.env.REACT_APP_API_BASE_URL || "";

async function safeJson(res) {
  const text = await res.text().catch(() => "");
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new Error(text || "Invalid JSON response");
  }
}

export async function getSettings({ signal } = {}) {
  const res = await fetch(`${API_BASE}/api/settings`, { signal });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Failed to load settings");
  }

  return safeJson(res);
}

/**
 * payload: { name }
 * Backend nên trả:
 * {
 *   apiKeys: [{ id, name, status, valueMasked, createdAt }],
 *   generatedKeyValue?: "ONE_TIME_SECRET"
 * }
 */
export async function upsertApiKey(payload, { signal } = {}) {
  const res = await fetch(`${API_BASE}/api/settings/api-keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
    signal,
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Failed to save API key");
  }

  return safeJson(res);
}

/**
 * payload: { enabled, endpoint, secret, events[] }
 * Backend trả:
 * { webhooks: { enabled, endpoint, secret, events } }
 */
export async function updateWebhooks(payload, { signal } = {}) {
  const res = await fetch(`${API_BASE}/api/settings/webhooks`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
    signal,
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Failed to save webhooks");
  }

  return safeJson(res);
}

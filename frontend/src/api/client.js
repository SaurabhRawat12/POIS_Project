// Tiny fetch-based client for the FastAPI backend on :8000.
//
// In production you'd read this from an env var; for local dev a hard-coded
// URL is fine and matches how Vite + uvicorn are typically run side-by-side.

const BASE_URL = "http://localhost:8000";

/** GET / — health check. Resolves with the service banner. */
export async function checkHealth() {
  const res = await fetch(`${BASE_URL}/`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * POST any endpoint with a JSON body.
 *
 * Example:
 *   const out = await callEndpoint("/pa13/check", { n: 561, k: 5 });
 */
export async function callEndpoint(path, body = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`HTTP ${res.status}: ${err}`);
  }
  return res.json();
}

/** GET endpoint helper — used for the lineage routes. */
export async function getEndpoint(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

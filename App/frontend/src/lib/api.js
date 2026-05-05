// Thin fetch wrapper around the Flask backend.
// CRA's `proxy` field in package.json routes /api/* to http://127.0.0.1:5000.

const BASE = "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API ${path} returned ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),
  primitives: () => request("/primitives"),
  build: (payload) =>
    request("/build", { method: "POST", body: JSON.stringify(payload) }),
  reduce: (payload) =>
    request("/reduce", { method: "POST", body: JSON.stringify(payload) }),
};

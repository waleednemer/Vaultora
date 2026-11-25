const API_URL = "/api";
let authToken = null; // في الذاكرة فقط، لا يُخزَّن في localStorage

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json" };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(API_URL + path, { ...options, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const fallback = res.status >= 500 ? "الخدمة غير متاحة حاليًا. حاول بعد قليل." : "حدث خطأ غير متوقع";
    throw new ApiError(body.error || fallback, res.status);
  }
  return res.status === 204 ? null : res.json();
}

const api = {
  setToken: (t) => { authToken = t; },
  vaultInfo: () => request("/vault"),
  setup: (body) => request("/vault", { method: "POST", body: JSON.stringify(body) }),
  login: (authKey) => request("/login", { method: "POST", body: JSON.stringify({ auth_key: authKey }) }),
  list: () => request("/entries"),
  create: (data) => request("/entries", { method: "POST", body: JSON.stringify({ data }) }),
  update: (id, data) => request(`/entries/${id}`, { method: "PUT", body: JSON.stringify({ data }) }),
  remove: (id) => request(`/entries/${id}`, { method: "DELETE" }),
};

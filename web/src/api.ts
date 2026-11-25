// Тонкая обёртка над fetch: same-origin (BFF проксирует API и добавляет identity).
export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...init });
  const txt = await r.text();
  let data: any = {};
  try { data = txt ? JSON.parse(txt) : {}; } catch { /* not json */ }
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data as T;
}

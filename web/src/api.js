// All requests are same-origin; the server's CSP blocks anything else.
async function get(path) {
  const res = await fetch(path, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

export const api = {
  meta: () => get('/api/meta'),
  audits: () => get('/api/audits'),
  audit: (id) => get(`/api/audits/${encodeURIComponent(id)}`),
  verify: (id) => get(`/api/audits/${encodeURIComponent(id)}/verify`),
  async simulate(scenario) {
    const res = await fetch(`/api/demo/${encodeURIComponent(scenario)}`, {
      method: 'POST',
      headers: { 'x-guardian-demo': '1' },
    });
    if (!res.ok) throw new Error(`simulation returned ${res.status}`);
    return res.json();
  },
};

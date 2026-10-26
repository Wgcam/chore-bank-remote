export const GET_PATHS = new Set(['/api/status','/api/state','/api/diagnostics']);
export const POST_PATHS = new Set(['/api/login','/api/logout','/api/transaction','/api/child','/api/chore','/api/chore/remove','/api/card','/api/card/remove','/api/enroll','/api/enroll/cancel','/api/language']);
export const encoder = new TextEncoder();
export function validateRequest(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  if (!['method','path','token','body'].every(k => v[k] === undefined || typeof v[k] === 'string')) return false;
  if (Object.keys(v).some(k => !['method','path','token','body'].includes(k))) return false;
  if (!(v.method === 'GET' ? GET_PATHS : v.method === 'POST' ? POST_PATHS : new Set()).has(v.path)) return false;
  if (v.token && !/^[a-fA-F0-9]{48}$/.test(v.token)) return false;
  if (v.method === 'GET') return !v.body;
  if (!v.body || encoder.encode(v.body).length > (v.path === '/api/login' ? 1024 : 2048)) return false;
  try {
    const body = JSON.parse(v.body);
    if (body === null || typeof body !== 'object' || Array.isArray(body)) return false;
    // The local child editor also accepts `active`; remote callers must not
    // bypass the local-only archive/reinstate route through that shared handler.
    if (v.path === '/api/child' && Object.keys(body).some(k => !['id','name','goal','goalUnit','goalCredits','goalCents','opening'].includes(k))) return false;
    return true;
  } catch { return false; }
}
export function decodeChunk(s) {
  if (typeof s !== 'string' || !s.length || s.length > 1024 || s.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) throw new Error('Invalid chunk');
  const raw=atob(s); if(raw.length>768 || btoa(raw)!==s) throw new Error('Invalid chunk');
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}

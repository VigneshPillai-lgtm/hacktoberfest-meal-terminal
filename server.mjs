import { createServer } from 'node:http';
import { readFile, mkdir, appendFile } from 'node:fs/promises';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { join, extname } from 'node:path';

const port = Number(process.env.PORT || 3000);
const origin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const root = join(process.cwd(), 'public');
const sessions = new Map();
const states = new Map();
const inFlightSubmissions = new Set();
const sessionSecret = process.env.SESSION_SECRET || token(32);
const meals = new Map([
  ['01', ['FRIED RICE', 'Classic vegetable fried rice with garden crunch & aromatic basmati']],
  ['02', ['SCHEZWAN FRIED RICE', 'Spicy Schezwan twist infused with fiery red chilies & garlic']],
  ['03', ['TRIPLE SCHEZWAN FRIED RICE', 'Layers of flavor & crispies with spiced wok gravy and fried ribbons']],
  ['04', ['CHILLY FRIED RICE', 'Spicy green chilly kick with bell peppers and spring onion reduction']],
  ['05', ['BUTTER GARLIC FRIED RICE', 'Rich garlic & butter aroma balanced with charred sweet corn & herbs']],
  ['06', ['HAKKA NOODLES', 'Classic street style wok noodles tossed with crunchy julienne greens']],
  ['07', ['SCHEZWAN NOODLES', 'Fiery chili paste infused noodles with scallions and crushed garlic']],
  ['08', ['CHILLY GARLIC NOODLES', 'Aromatic roasted garlic paired with dark chili soy glaze and crisp sprouts']],
  ['09', ['SINGAPORE NOODLES', 'Delicate yellow curry powder infused vermicelli tossed with mixed vegetables']],
  ['10', ['BUTTER GARLIC NOODLES', 'Velvety butter garlic coating with cracked black pepper and green scallions']]
]);
const submitted = new Map();
const roster = new Set((process.env.FACULTY_ROSTER_NAMES || '').split(',').map(normalize).filter(Boolean));

function normalize(value = '') { return value.trim().replace(/\s+/g, ' ').toUpperCase(); }
function token(bytes = 24) { return randomBytes(bytes).toString('base64url'); }
function send(res, status, data, headers = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers }); res.end(JSON.stringify(data)); }
function signature(id) { return createHmac('sha256', sessionSecret).update(id).digest('base64url'); }
function cookie(req) {
  const value = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('hack_session='))?.slice(13);
  if (!value) return null; const [id, sig] = value.split('.'); return id && sig && safeEqual(sig, signature(id)) ? id : null;
}
function session(req) { return sessions.get(cookie(req)); }
function safeEqual(a, b) { const x = Buffer.from(a); const y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
function ensureSession(req, res) {
  const existing = cookie(req); if (existing && sessions.has(existing)) return [existing, sessions.get(existing)];
  const id = token(); const value = {}; sessions.set(id, value);
  res.setHeader('set-cookie', `hack_session=${id}.${signature(id)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=14400${origin.startsWith('https:') ? '; Secure' : ''}`);
  return [id, value];
}
async function body(req) { let raw = ''; for await (const part of req) { raw += part; if (raw.length > 15000) throw Error('Request too large'); } try { return JSON.parse(raw || '{}'); } catch { throw Error('Invalid JSON'); } }
function identityOf(s) { return s?.identity && s?.role ? s.identity : null; }
async function sheets(payload) {
  const endpoint = process.env.GOOGLE_SHEETS_ENDPOINT;
  if (!endpoint) throw Error('Google Sheets endpoint is not configured.');
  const headers = { 'content-type': 'application/json' };
  if (process.env.GOOGLE_SHEETS_BEARER_TOKEN) headers.authorization = `Bearer ${process.env.GOOGLE_SHEETS_BEARER_TOKEN}`;
  const result = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(10000) });
  if (!result.ok) throw Error('Recording endpoint rejected the selection.');
}
function login(sessionValue, role, identity, github = null) { sessionValue.role = role; sessionValue.identity = identity; sessionValue.github = github; }

createServer(async (req, res) => {
  const url = new URL(req.url, origin);
  try {
    if (url.pathname === '/api/session') { const s = session(req); return send(res, 200, { authenticated: Boolean(identityOf(s)), role: s?.role, identity: s?.identity, github: s?.github }); }
    if (url.pathname === '/auth/github' && req.method === 'GET') {
      if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) return send(res, 503, { error: 'GitHub OAuth is not configured.' });
      const [, s] = ensureSession(req, res); const state = token(); states.set(state, { session: s, expires: Date.now() + 600000 });
      const callback = process.env.GITHUB_REDIRECT_URI || `${origin}/auth/github/callback`;
      res.writeHead(302, { location: `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(process.env.GITHUB_CLIENT_ID)}&redirect_uri=${encodeURIComponent(callback)}&scope=read:user&state=${state}` }); return res.end();
    }
    if (url.pathname === '/auth/github/callback' && req.method === 'GET') {
      const entry = states.get(url.searchParams.get('state')); states.delete(url.searchParams.get('state'));
      if (!entry || entry.expires < Date.now() || !url.searchParams.get('code')) { res.writeHead(302, { location: '/?auth=failed' }); return res.end(); }
      const callback = process.env.GITHUB_REDIRECT_URI || `${origin}/auth/github/callback`;
      const exchange = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: url.searchParams.get('code'), redirect_uri: callback }) });
      const credential = await exchange.json(); if (!credential.access_token) throw Error('GitHub code exchange failed.');
      const profileResponse = await fetch('https://api.github.com/user', { headers: { authorization: `Bearer ${credential.access_token}`, 'user-agent': 'hacktoberfest-meal-terminal', accept: 'application/vnd.github+json' } });
      const profile = await profileResponse.json(); if (!profileResponse.ok || !profile.id || !profile.login) throw Error('GitHub profile verification failed.');
      login(entry.session, 'STUDENT', `github:${profile.id}`, { login: profile.login, name: profile.name || profile.login });
      res.writeHead(302, { location: '/#/meal-matrix' }); return res.end();
    }
    if (url.pathname === '/api/faculty/verify' && req.method === 'POST') {
      const [, s] = ensureSession(req, res); const { name } = await body(req); const key = normalize(name);
      if (!key || !roster.has(key)) return send(res, 403, { error: 'ROSTER QUERY NEGATIVE. Faculty identity not authorized.' });
      login(s, 'FACULTY', `faculty:${key}`, { name: key }); return send(res, 200, { ok: true, name: key });
    }
    if (url.pathname === '/api/submit' && req.method === 'POST') {
      const s = session(req); const identity = identityOf(s); if (!identity) return send(res, 401, { error: 'Identity verification required.' });
      const { mealId } = await body(req); const meal = meals.get(mealId); if (!meal) return send(res, 400, { error: 'Invalid meal selection.' });
      if (submitted.has(identity) || inFlightSubmissions.has(identity)) return send(res, 409, { error: 'A meal has already been confirmed for this identity.' });
      const record = { timestamp: new Date().toISOString(), role: s.role, identity, githubUsername: s.github?.login || '', name: s.github?.name || s.identity.replace('faculty:', ''), mealId, meal: meal[0], status: 'CONFIRMED', token: `H26-${randomBytes(5).toString('hex').toUpperCase()}` };
      inFlightSubmissions.add(identity);
      try { await sheets(record); submitted.set(identity, record); return send(res, 201, { ok: true, record }); }
      finally { inFlightSubmissions.delete(identity); }
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') { sessions.delete(cookie(req)); return send(res, 200, { ok: true }, { 'set-cookie': 'hack_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' }); }
    if (req.method === 'GET') {
      const requested = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (requested.includes('..')) throw Error('Not found');
      const content = await readFile(join(root, requested));
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
      res.writeHead(200, { 'content-type': `${types[extname(requested)] || 'application/octet-stream'}; charset=utf-8`, 'cache-control': 'no-store' }); return res.end(content);
    }
    send(res, 404, { error: 'Not found' });
  } catch (error) { send(res, 500, { error: error.message || 'Terminal fault.' }); }
}).listen(port, () => console.log(`Hack Lunch terminal online at ${origin}`));

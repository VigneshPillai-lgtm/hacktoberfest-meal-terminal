import { createServer } from 'node:http';
import { readFile, mkdir, appendFile } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { join, extname } from 'node:path';

const port = Number(process.env.PORT || 3000);
const origin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const root = join(process.cwd(), 'public');
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

function normalize(value = '') { return value.trim().replace(/\s+/g, ' ').toUpperCase(); }
function normalizeRollNumber(value = '') { return String(value).trim().toUpperCase(); }
function validRollNumber(value) { return /^[A-Z0-9-]{4,20}$/.test(value); }
function token(bytes = 24) { return randomBytes(bytes).toString('base64url'); }
function sign(value) { return createHmac('sha256', sessionSecret).update(value).digest('base64url'); }
function send(res, status, data, headers = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers }); res.end(JSON.stringify(data)); }
function cookie(req, name) {
  return (req.headers.cookie || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${name}=`))?.slice(name.length + 1);
}
function session(req) {
  const value = cookie(req, 'hack_session');
  if (!value) return null;
  const [payload, signature] = value.split('.');
  if (!payload || !signature || !safeEqual(signature, sign(payload))) return null;
  try {
    const result = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return result.expiresAt > Date.now() ? result : null;
  } catch { return null; }
}
function safeEqual(a, b) { const x = Buffer.from(a); const y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
function secureCookie() { return origin.startsWith('https:') ? '; Secure' : ''; }
function oauthStateCookie(state, rollNumber) {
  const iv = randomBytes(12);
  const key = createHash('sha256').update(sessionSecret).digest();
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify({ state, rollNumber }), 'utf8'), cipher.final()]);
  const payload = Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
  return `oauth_state=${payload}; HttpOnly; SameSite=Lax; Path=/auth/github/callback; Max-Age=600${secureCookie()}`;
}
function readOauthState(value) {
  try {
    const packed = Buffer.from(value, 'base64url');
    if (packed.length <= 28) return null;
    const key = createHash('sha256').update(sessionSecret).digest();
    const decipher = createDecipheriv('aes-256-gcm', key, packed.subarray(0, 12));
    decipher.setAuthTag(packed.subarray(12, 28));
    const decoded = Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString('utf8');
    return JSON.parse(decoded);
  } catch { return null; }
}
function clearOauthStateCookie() { return `oauth_state=; HttpOnly; SameSite=Lax; Path=/auth/github/callback; Max-Age=0${secureCookie()}`; }
function sessionCookie(value) {
  const payload = Buffer.from(JSON.stringify({ ...value, expiresAt: Date.now() + 14400000 })).toString('base64url');
  return `hack_session=${payload}.${sign(payload)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=14400${secureCookie()}`;
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
function login(res, role, identity, github = null, additionalCookies = []) {
  res.setHeader('set-cookie', [sessionCookie({ role, identity, github }), ...additionalCookies]);
}

createServer(async (req, res) => {
  const url = new URL(req.url, origin);
  try {
    if (url.pathname === '/api/session') { const s = session(req); return send(res, 200, { authenticated: Boolean(identityOf(s)), role: s?.role, identity: s?.identity, github: s?.github }); }
    if (url.pathname === '/api/student/oauth/start' && req.method === 'POST') {
      if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) return send(res, 503, { error: 'GitHub OAuth is not configured.' });
      const { rollNumber: inputRollNumber } = await body(req);
      const rollNumber = normalizeRollNumber(inputRollNumber);
      if (!validRollNumber(rollNumber)) return send(res, 400, { error: 'Enter a valid roll number using 4–20 letters or numbers.' });
      const state = token(); res.setHeader('set-cookie', oauthStateCookie(state, rollNumber));
      const callback = process.env.GITHUB_REDIRECT_URI || `${origin}/auth/github/callback`;
      return send(res, 200, { url: `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(process.env.GITHUB_CLIENT_ID)}&redirect_uri=${encodeURIComponent(callback)}&scope=read:user&state=${state}` });
    }
    if (url.pathname === '/auth/github/callback' && req.method === 'GET') {
      const returnedState = url.searchParams.get('state');
      const stateData = readOauthState(cookie(req, 'oauth_state') || '');
      const stateIsValid = returnedState && stateData?.state === returnedState && validRollNumber(stateData.rollNumber);
      if (!stateIsValid || !url.searchParams.get('code')) { res.setHeader('set-cookie', clearOauthStateCookie()); res.writeHead(302, { location: '/?auth=failed' }); return res.end(); }
      const callback = process.env.GITHUB_REDIRECT_URI || `${origin}/auth/github/callback`;
      const exchange = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: url.searchParams.get('code'), redirect_uri: callback }) });
      const credential = await exchange.json(); if (!credential.access_token) throw Error('GitHub code exchange failed.');
      const profileResponse = await fetch('https://api.github.com/user', { headers: { authorization: `Bearer ${credential.access_token}`, 'user-agent': 'hacktoberfest-meal-terminal', accept: 'application/vnd.github+json' } });
      const profile = await profileResponse.json(); if (!profileResponse.ok || !profile.id || !profile.login) throw Error('GitHub profile verification failed.');
      login(res, 'STUDENT', `github:${profile.id}`, { login: profile.login, name: profile.name || profile.login, rollNumber: stateData.rollNumber }, [clearOauthStateCookie()]);
      res.writeHead(302, { location: '/#/meal-matrix' }); return res.end();
    }
    if (url.pathname === '/api/faculty/verify' && req.method === 'POST') {
      const { name } = await body(req); const key = normalize(name);
      if (!key) return send(res, 400, { error: 'Enter a faculty name to continue.' });
      login(res, 'FACULTY', `faculty:${key}`, { name: key }); return send(res, 200, { ok: true, name: key });
    }
    if (url.pathname === '/api/submit' && req.method === 'POST') {
      const s = session(req); const identity = identityOf(s); if (!identity) return send(res, 401, { error: 'Identity verification required.' });
      const { mealId } = await body(req); const meal = meals.get(mealId); if (!meal) return send(res, 400, { error: 'Invalid meal selection.' });
      if (submitted.has(identity) || inFlightSubmissions.has(identity)) return send(res, 409, { error: 'A meal has already been confirmed for this identity.' });
      const record = { timestamp: new Date().toISOString(), role: s.role, identity, name: s.github?.name || s.identity.replace('faculty:', ''), githubUsername: s.github?.login || '', rollNumber: s.role === 'STUDENT' ? s.github?.rollNumber || '' : '', mealId, meal: meal[0], status: 'CONFIRMED', token: `H26-${randomBytes(5).toString('hex').toUpperCase()}` };
      inFlightSubmissions.add(identity);
      try { await sheets(record); submitted.set(identity, record); return send(res, 201, { ok: true, record }); }
      finally { inFlightSubmissions.delete(identity); }
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') { return send(res, 200, { ok: true }, { 'set-cookie': `hack_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureCookie()}` }); }
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

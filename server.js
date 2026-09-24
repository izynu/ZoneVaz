// ============================================================
//  ZoneVaz Studio — Secure Backend Server (Zero Dependencies)
//  Node.js built-in modules only. Run with: node server.js
//
//  Provides:
//   • Static hosting of the site
//   • Real authentication (scrypt-hashed passwords, server sessions)
//   • Per-user library & playlists (stored server-side)
//   • Admin control panel API (server-side, no plaintext passwords)
//   • Secure API-key proxy (keys never leave the server)
//   • Streaming proxy for MP3 downloads (fixes CORS blocking)
//   • Lyrics proxy (lrclib.net)
//   • JSON persistence in ./data
// ============================================================

const http = require('http');
const https = require('https');
const fsp = require('fs').promises;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const STATIC_DIR = ROOT;
const DEFAULT_ADMIN_PASS = 'zynu2026';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_BODY = 30 * 1024 * 1024; // 30 MB for restores/uploads
const MAX_LOGIN_ATTEMPTS = 10;
const RATE_WINDOW = 5 * 60 * 1000;

// ------------------------------------------------------------------
// Storage helpers (JSON files in ./data)
// ------------------------------------------------------------------
async function ensureDataDir() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
}

async function readJson(file, fallback) {
  try {
    const raw = await fsp.readFile(path.join(DATA_DIR, file), 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

async function writeJson(file, data) {
  const target = path.join(DATA_DIR, file);
  const tmp = target + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
  await fsp.rename(tmp, target);
}

// ------------------------------------------------------------------
// Password hashing (scrypt — NIST recommended, built-in)
// ------------------------------------------------------------------
function makeSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}

// ------------------------------------------------------------------
// State
// ------------------------------------------------------------------
let settings = null;
let sessions = {}; // token -> {userId, isAdmin, csrf, exp}
let rate = new Map(); // ip:method -> {count, reset}

async function loadSettings() {
  settings = await readJson('settings.json', null);
  if (!settings) {
    const initialSalt = makeSalt();
    settings = {
      adminPassSalt: initialSalt,
      adminPassHash: hashPassword(DEFAULT_ADMIN_PASS, initialSalt),
      banner: '',
      apiKeys: [
        '18ec28704fmsh289906a33589844p13ddd7jsn4faff9883a7d',
        '8a59f4306dmsh406b4268969c6dep14656djsnc11d8f7f4852',
        '250d9a4280mshd3898b43c92a32bp15c7ecjsn05e64955903c',
        'afc0e0f25fmsh982b1ec63cc3355p1b1cfcjsndfcb3e981190',
        '76a7c31a63mshc69bdd7f44458f4p1fd655jsneb626c23425a'
      ],
      palette: { pink: '#ff9ebd', purple: '#c49fff', bg: '#0c0511', card: '#130919' }
    };
    await saveSettings();
    console.log('[ZoneVaz] Fresh install — admin passcode is: ' + DEFAULT_ADMIN_PASS + ' (change it in Settings!)');
  }
  // ensure fields exist on legacy configs
  settings.banner = settings.banner || '';
  settings.apiKeys = Array.isArray(settings.apiKeys) ? settings.apiKeys.filter(Boolean) : [];
  settings.palette = settings.palette || { pink: '#ff9ebd', purple: '#c49fff', bg: '#0c0511', card: '#130919' };
}

async function saveSettings() {
  await writeJson('settings.json', settings);
}

async function loadSessions() {
  sessions = await readJson('sessions.json', {});
  // Drop expired
  const now = Date.now();
  for (const t of Object.keys(sessions)) {
    if (!sessions[t].exp || sessions[t].exp < now) delete sessions[t];
  }
}

async function persistSessions() {
  await writeJson('sessions.json', sessions);
}

function addLog(category, details, status) {
  return readJson('logs.json', []).then(logs => {
    logs.unshift({
      id: 'log_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
      timestamp: new Date().toLocaleString(),
      category: category,
      details: String(details || ''),
      status: status || 'Success'
    });
    return writeJson('logs.json', logs.slice(0, 300));
  });
}

// ------------------------------------------------------------------
// HTTP helper: fetch upstream (http/https) with redirects
// ------------------------------------------------------------------
function fetchUpstream(url, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: headers || {} }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchUpstream(new URL(res.headers.location, url).toString(), headers, timeoutMs));
      }
      resolve(res);
    });
    req.setTimeout(timeoutMs || 20000, () => req.destroy(new Error('Upstream timeout')));
    req.on('error', reject);
  });
}

function collectBody(res, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    res.on('data', c => {
      size += c.length;
      if (size > (limit || MAX_BODY)) {
        res.destroy();
        return reject(new Error('Response too large'));
      }
      chunks.push(c);
    });
    res.on('end', () => resolve(Buffer.concat(chunks)));
    res.on('error', reject);
  });
}

// ------------------------------------------------------------------
// Cookie & session helpers
// ------------------------------------------------------------------
function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  });
  return out;
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.zv_sid;
  if (!token || !sessions[token]) return null;
  const s = sessions[token];
  if (s.exp && s.exp < Date.now()) {
    delete sessions[token];
    return null;
  }
  return { token, ...s };
}

function createSession(payload) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = Object.assign({
    csrf: crypto.randomBytes(18).toString('hex'),
    exp: Date.now() + SESSION_TTL
  }, payload);
  return token;
}

function sessionCookie(token) {
  return 'zv_sid=' + encodeURIComponent(token) + '; HttpOnly; Path=/; SameSite=Strict; Max-Age=' + Math.floor(SESSION_TTL / 1000);
}

function clearCookie() {
  return 'zv_sid=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0';
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req) {
  return collectBody(req).catch(() => Buffer.alloc(0)).then(buf => {
    if (!buf.length) return {};
    try { return JSON.parse(buf.toString('utf8')); } catch (e) { return {}; }
  });
}

// ------------------------------------------------------------------
// Simple per-IP rate limiter (login endpoints)
// ------------------------------------------------------------------
function checkRate(ip, key, limit) {
  const now = Date.now();
  const id = ip + ':' + key;
  let rec = rate.get(id);
  if (!rec || rec.reset < now) {
    rec = { count: 0, reset: now + RATE_WINDOW };
    rate.set(id, rec);
  }
  rec.count++;
  if (rec.count > (limit || MAX_LOGIN_ATTEMPTS)) return false;
  return true;
}

// ------------------------------------------------------------------
// Auth helpers
// ------------------------------------------------------------------
function requireUser(req, res) {
  const s = getSession(req);
  if (!s || !s.userId) { json(res, 401, { error: 'Please login first.' }); return null; }
  return s;
}

function requireAdmin(req, res) {
  const s = getSession(req);
  if (!s || !s.isAdmin) { json(res, 403, { error: 'Admin access required.' }); return null; }
  return s;
}

function csrfOk(req) {
  const s = getSession(req);
  if (!s) return false;
  return (req.headers['x-csrf-token'] || '') === s.csrf;
}

// ------------------------------------------------------------------
// Rotating RapidAPI proxy (server-side — keys never exposed)
// ------------------------------------------------------------------
async function rapidApiGet(endpoint, query) {
  const keys = settings.apiKeys.slice();
  if (!keys.length) throw new Error('No API keys configured on the server.');
  // Try each key in random order
  keys.sort(() => 0.5 - Math.random());
  let lastErr = null;
  for (const key of keys) {
    try {
      const url = 'https://spotify-downloader9.p.rapidapi.com/' + endpoint + '?' + query;
      const res = await fetchUpstream(url, {
        'x-rapidapi-host': 'spotify-downloader9.p.rapidapi.com',
        'x-rapidapi-key': key
      });
      if (res.statusCode === 429 || res.statusCode >= 500) {
        res.resume();
        lastErr = new Error('Upstream status ' + res.statusCode);
        continue;
      }
      if (res.statusCode !== 200) {
        res.resume();
        lastErr = new Error('Upstream status ' + res.statusCode);
        continue;
      }
      const buf = await collectBody(res);
      return JSON.parse(buf.toString('utf8'));
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('All API keys exhausted.');
}

// ------------------------------------------------------------------
// Admin API-key rotation search & download
// ------------------------------------------------------------------
async function apiSearch(q) {
  return rapidApiGet('search', 'q=' + encodeURIComponent(q) + '&type=tracks');
}
async function apiDownloadLink(trackId) {
  const data = await rapidApiGet('downloadSong', 'songId=' + encodeURIComponent('https://open.spotify.com/track/' + trackId));
  return data && (data.data && (data.data.downloadLink || data.data.link)) || data.downloadLink || data.link || null;
}

// ------------------------------------------------------------------
// Lyrics proxy (lrclib.net)
// ------------------------------------------------------------------
async function apiLyrics(q) {
  const res = await fetchUpstream('https://lrclib.net/api/search?q=' + encodeURIComponent(q));
  if (res.statusCode !== 200) { res.resume(); throw new Error('Lyrics upstream ' + res.statusCode); }
  const buf = await collectBody(res);
  return JSON.parse(buf.toString('utf8'));
}

// ------------------------------------------------------------------
// Helpers for user data
// ------------------------------------------------------------------
function sanitizeUser(u) {
  return { id: u.id, name: u.name, email: u.email, avatar: u.avatar || '☁️', registeredAt: u.registeredAt || 'Prior Member' };
}

// ------------------------------------------------------------------
// The API router
// ------------------------------------------------------------------
async function handleApi(req, res, pathname, query, body, ip) {
  const method = req.method;
  const seg = pathname.split('/').filter(Boolean); // e.g. ['api','tracks','z1']
  const isPost = method === 'POST';
  const isPut = method === 'PUT';
  const isDel = method === 'DELETE';
  const isGet = method === 'GET';

  // ----- CSRF guard for state-changing requests -----
  if (isPost || isPut || isDel) {
    if (!csrfOk(req)) {
      return json(res, 403, { error: 'Invalid session token. Refresh the page and try again.' });
    }
  }

  // ================= AUTH =================
  if (pathname === '/api/bootstrap') {
    let s = getSession(req);
    if (!s) {
      const token = createSession({});
      s = sessions[token];
      res.setHeader('Set-Cookie', sessionCookie(token));
    }
    let user = null;
    if (s.userId) {
      const users = await readJson('users.json', []);
      user = sanitizeUser(users.find(u => u.id === s.userId)) || null;
    }
    return json(res, 200, {
      user: user,
      isAdmin: !!(s && s.isAdmin),
      csrf: s ? s.csrf : null,
      config: {
        banner: settings.banner,
        palette: settings.palette
      }
    });
  }

  if (pathname === '/api/register' && isPost) {
    const ipKey = ip || 'unknown';
    if (!checkRate(ipKey, 'register')) return json(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const pass = String(body.pass || '');
    const avatar = String(body.avatar || '☁️').trim();
    if (!name || !email || !pass) return json(res, 400, { error: 'Please fill all fields!' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, 400, { error: 'Please enter a valid email address.' });
    if (pass.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters long.' });
    if (name.length > 40) return json(res, 400, { error: 'Name is too long.' });
    const users = await readJson('users.json', []);
    if (users.some(u => u.email === email)) return json(res, 409, { error: 'An account with this email already exists!' });
    const salt = makeSalt();
    const newUser = {
      id: 'u_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
      name,
      email,
      passHash: hashPassword(pass, salt),
      salt,
      avatar,
      registeredAt: new Date().toLocaleDateString()
    };
    users.push(newUser);
    await writeJson('users.json', users);
    // Preserve the existing session token so the CSRF token stays valid
    const existing = getSession(req);
    const token = existing ? existing.token : createSession({});
    sessions[token] = Object.assign({}, sessions[token] || {}, { userId: newUser.id });
    res.setHeader('Set-Cookie', sessionCookie(token));
    await addLog('Registration', 'New audiophile joined: ' + name + ' (' + email + ')', 'Registered');
    return json(res, 200, { user: sanitizeUser(newUser) });
  }

  if (pathname === '/api/login' && isPost) {
    const ipKey = ip || 'unknown';
    if (!checkRate(ipKey, 'login')) return json(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
    const email = String(body.email || '').trim().toLowerCase();
    const pass = String(body.pass || '');
    const users = await readJson('users.json', []);
    const user = users.find(u => u.email === email);
    if (!user || hashPassword(pass, user.salt) !== user.passHash) {
      await addLog('Security', 'Failed sign-in attempt for email: "' + email + '"', 'Blocked');
      return json(res, 401, { error: 'Invalid email or password!' });
    }
    const existing = getSession(req);
    const token = existing ? existing.token : createSession({});
    sessions[token] = Object.assign({}, sessions[token] || {}, { userId: user.id });
    res.setHeader('Set-Cookie', sessionCookie(token));
    await addLog('Auth', 'User signed in: ' + user.name + ' (' + email + ')', 'Success');
    return json(res, 200, { user: sanitizeUser(user) });
  }

  if (pathname === '/api/logout' && isPost) {
    const s = getSession(req);
    if (s) { delete sessions[s.token]; persistSessions(); }
    res.setHeader('Set-Cookie', clearCookie());
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/admin/login' && isPost) {
    const ipKey = ip || 'unknown';
    if (!checkRate(ipKey, 'admin')) return json(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
    const pass = String(body.passcode || '');
    const s = getSession(req);
    if (hashPassword(pass, settings.adminPassSalt) !== settings.adminPassHash) {
      await addLog('Security Alert', 'Failed admin login attempt', 'Blocked');
      return json(res, 401, { error: 'Access Denied: Invalid Passcode!' });
    }
    const token = (s && s.token) || createSession({});
    sessions[token] = Object.assign({}, sessions[token], { isAdmin: true });
    res.setHeader('Set-Cookie', sessionCookie(token));
    await addLog('Admin Gate', 'Admin unlocked the Studio', 'Success');
    return json(res, 200, { ok: true });
  }

  // ================= PROFILE =================
  if (pathname === '/api/profile' && (isPost || isPut)) {
    const s = requireUser(req, res); if (!s) return;
    const users = await readJson('users.json', []);
    const idx = users.findIndex(u => u.id === s.userId);
    if (idx === -1) return json(res, 404, { error: 'User not found.' });
    const u = users[idx];
    if (typeof body.name === 'string') {
      const name = body.name.trim();
      if (!name || name.length > 40) return json(res, 400, { error: 'Name cannot be empty or too long!' });
      u.name = name;
    }
    if (typeof body.avatar === 'string') {
      if (body.avatar.length > 2 * 1024 * 1024) return json(res, 400, { error: 'Avatar image too large.' });
      u.avatar = body.avatar;
    }
    await writeJson('users.json', users);
    await addLog('Profile Update', 'User updated profile: ' + u.name, 'Success');
    return json(res, 200, { user: sanitizeUser(u) });
  }

  if (pathname === '/api/profile/security' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const users = await readJson('users.json', []);
    const idx = users.findIndex(u => u.id === s.userId);
    if (idx === -1) return json(res, 404, { error: 'User not found.' });
    const u = users[idx];
    const oldPass = String(body.oldPass || '');
    if (hashPassword(oldPass, u.salt) !== u.passHash) return json(res, 403, { error: 'Incorrect current password.' });
    if (body.newEmail) {
      const email = String(body.newEmail).trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, 400, { error: 'Invalid email address.' });
      if (users.some(x => x.email === email && x.id !== u.id)) return json(res, 409, { error: 'This email is already in use.' });
      u.email = email;
    }
    if (body.newPass) {
      if (String(body.newPass).length < 6) return json(res, 400, { error: 'New password must be at least 6 characters.' });
      u.salt = makeSalt();
      u.passHash = hashPassword(body.newPass, u.salt);
    }
    await writeJson('users.json', users);
    await addLog('Security', 'User updated credentials: ' + u.name, 'Success');
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/profile/delete' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const users = await readJson('users.json', []);
    const idx = users.findIndex(u => u.id === s.userId);
    if (idx === -1) return json(res, 404, { error: 'User not found.' });
    const name = users[idx].name;
    users.splice(idx, 1);
    await writeJson('users.json', users);
    // Remove their personal data
    const lib = await readJson('library.json', {});
    const pl = await readJson('playlists.json', {});
    delete lib[s.userId]; delete pl[s.userId];
    await writeJson('library.json', lib);
    await writeJson('playlists.json', pl);
    delete sessions[s.token];
    await addLog('User Deletion', 'User self-deleted account: ' + name, 'Warning');
    res.setHeader('Set-Cookie', clearCookie());
    return json(res, 200, { ok: true });
  }

  // ================= TRACKS (admin-managed, public read) =================
  if (pathname === '/api/tracks' && isGet) {
    const tracks = await readJson('tracks.json', []);
    return json(res, 200, { tracks });
  }

  if (pathname === '/api/tracks' && isPost) {
    const s = requireAdmin(req, res); if (!s) return;
    const b = body.track || body;
    const title = String(b.title || '').trim();
    if (!title) return json(res, 400, { error: 'Title is mandatory!' });
    const tracks = await readJson('tracks.json', []);
    const track = {
      id: 'z' + Date.now(),
      title,
      artist: String(b.artist || 'Zynu').trim() || 'Zynu',
      tag: String(b.tag || '').trim() || 'Original',
      details: String(b.details || '').trim(),
      cover: b.cover || '',
      audioUrl: b.audioUrl || '',
      pinned: !!b.pinned,
      links: {
        spotify: String(b.links && b.links.spotify || '').trim(),
        youtube: String(b.links && b.links.youtube || '').trim(),
        apple: String(b.links && b.links.apple || '').trim(),
        soundcloud: String(b.links && b.links.soundcloud || '').trim()
      }
    };
    tracks.unshift(track);
    await writeJson('tracks.json', tracks);
    await addLog('Track', 'Published new original track: "' + title + '"', 'Created');
    return json(res, 200, { track });
  }

  if (seg[0] === 'api' && seg[1] === 'tracks' && seg[2] && (isPut || isDel)) {
    const s = requireAdmin(req, res); if (!s) return;
    const id = seg[2];
    let tracks = await readJson('tracks.json', []);
    const idx = tracks.findIndex(t => t.id === id);
    if (idx === -1) return json(res, 404, { error: 'Track not found.' });
    if (isDel) {
      const title = tracks[idx].title;
      tracks.splice(idx, 1);
      await writeJson('tracks.json', tracks);
      await addLog('Track', 'Deleted track: "' + title + '"', 'Deleted');
      return json(res, 200, { ok: true });
    }
    const b = body.track || body;
    const title = String(b.title || '').trim();
    if (!title) return json(res, 400, { error: 'Title is mandatory!' });
    tracks[idx] = Object.assign({}, tracks[idx], {
      title,
      artist: String(b.artist || tracks[idx].artist || 'Zynu').trim(),
      tag: String(b.tag || '').trim() || 'Original',
      details: String(b.details || '').trim(),
      cover: typeof b.cover === 'string' ? b.cover : tracks[idx].cover,
      audioUrl: typeof b.audioUrl === 'string' ? b.audioUrl : tracks[idx].audioUrl,
      pinned: !!b.pinned,
      links: {
        spotify: String(b.links && b.links.spotify || '').trim(),
        youtube: String(b.links && b.links.youtube || '').trim(),
        apple: String(b.links && b.links.apple || '').trim(),
        soundcloud: String(b.links && b.links.soundcloud || '').trim()
      }
    });
    await writeJson('tracks.json', tracks);
    await addLog('Track', 'Updated details for track: "' + title + '"', 'Updated');
    return json(res, 200, { track: tracks[idx] });
  }

  // ================= LIBRARY (per-user) =================
  if (pathname === '/api/library' && isGet) {
    const s = requireUser(req, res); if (!s) return;
    const lib = await readJson('library.json', {});
    return json(res, 200, { library: lib[s.userId] || [] });
  }

  if (pathname === '/api/library' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const trackId = String(body.trackId || '');
    const title = String(body.title || '').trim().slice(0, 200);
    const artist = String(body.artist || '').trim().slice(0, 200);
    if (!trackId) return json(res, 400, { error: 'Missing track.' });
    const lib = await readJson('library.json', {});
    let arr = lib[s.userId] || [];
    const idx = arr.findIndex(t => t.trackId === trackId);
    let added = false;
    if (idx === -1) {
      arr.unshift({ trackId, title, artist, addedAt: Date.now() });
      added = true;
    } else {
      arr.splice(idx, 1);
    }
    arr = arr.slice(0, 500);
    lib[s.userId] = arr;
    await writeJson('library.json', lib);
    return json(res, 200, { library: arr, added });
  }

  // ================= PLAYLISTS (per-user) =================
  if (pathname === '/api/playlists' && isGet) {
    const s = requireUser(req, res); if (!s) return;
    const pl = await readJson('playlists.json', {});
    return json(res, 200, { playlists: pl[s.userId] || [] });
  }

  if (pathname === '/api/playlists' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const name = String(body.name || '').trim().slice(0, 80);
    if (!name) return json(res, 400, { error: 'Please enter a playlist name!' });
    const all = await readJson('playlists.json', {});
    const arr = all[s.userId] || [];
    arr.unshift({ id: 'pl_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'), name, tracks: [] });
    all[s.userId] = arr.slice(0, 200);
    await writeJson('playlists.json', all);
    return json(res, 200, { playlists: all[s.userId] });
  }

  if (seg[0] === 'api' && seg[1] === 'playlists' && seg[2] && isDel) {
    const s = requireUser(req, res); if (!s) return;
    const id = seg[2];
    const all = await readJson('playlists.json', {});
    let arr = all[s.userId] || [];
    arr = arr.filter(p => p.id !== id);
    all[s.userId] = arr;
    await writeJson('playlists.json', all);
    return json(res, 200, { playlists: arr });
  }

  if (seg[0] === 'api' && seg[1] === 'playlists' && seg[2] && seg[3] === 'tracks' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const all = await readJson('playlists.json', {});
    const arr = all[s.userId] || [];
    const pl = arr.find(p => p.id === seg[2]);
    if (!pl) return json(res, 404, { error: 'Playlist not found.' });
    if (!pl.tracks.some(t => t.trackId === body.trackId)) {
      pl.tracks.push({
        trackId: String(body.trackId || ''),
        title: String(body.title || '').slice(0, 200),
        artist: String(body.artist || '').slice(0, 200)
      });
      await writeJson('playlists.json', all);
    }
    return json(res, 200, { playlists: arr });
  }

  if (seg[0] === 'api' && seg[1] === 'playlists' && seg[2] && seg[3] === 'tracks' && seg[4] && isDel) {
    const s = requireUser(req, res); if (!s) return;
    const all = await readJson('playlists.json', {});
    const arr = all[s.userId] || [];
    const pl = arr.find(p => p.id === seg[2]);
    if (pl) {
      pl.tracks = pl.tracks.filter(t => t.trackId !== seg[4]);
      await writeJson('playlists.json', all);
    }
    return json(res, 200, { playlists: arr });
  }

  // ================= REQUESTS / INBOX =================
  if (pathname === '/api/requests' && isPost) {
    const s = requireUser(req, res); if (!s) return;
    const title = String(body.songTitle || body.title || '').trim().slice(0, 200);
    const note = String(body.note || '').trim().slice(0, 2000);
    if (!title) return json(res, 400, { error: 'Please enter a song title or vibe!' });
    const inbox = await readJson('inbox.json', []);
    const user = (await readJson('users.json', [])).find(u => u.id === s.userId);
    inbox.unshift({ date: new Date().toLocaleDateString(), sender: user ? user.name : 'Anonymous', songTitle: title, note });
    await writeJson('inbox.json', inbox.slice(0, 500));
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/requests' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    return json(res, 200, { inbox: await readJson('inbox.json', []) });
  }

  if (seg[0] === 'api' && seg[1] === 'requests' && seg[2] === 'clear' && isDel) {
    const s = requireAdmin(req, res); if (!s) return;
    await writeJson('inbox.json', []);
    await addLog('Admin', 'Inbox cleared', 'Success');
    return json(res, 200, { inbox: [] });
  }

  if (seg[0] === 'api' && seg[1] === 'requests' && seg[2] === 'replace' && isPost) {
    const s = requireAdmin(req, res); if (!s) return;
    const inbox = Array.isArray(body.inbox) ? body.inbox.slice(0, 500) : [];
    await writeJson('inbox.json', inbox);
    return json(res, 200, { inbox });
  }

  // ================= SEARCHES =================
  if (pathname === '/api/searches' && isPost) {
    const q = String(body.query || '').trim().slice(0, 200);
    if (q) {
      const searches = await readJson('searches.json', []);
      searches.unshift({ time: new Date().toLocaleString(), query: q });
      await writeJson('searches.json', searches.slice(0, 300));
    }
    return json(res, 200, { ok: true });
  }

  if (pathname === '/api/searches' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    return json(res, 200, { searches: (await readJson('searches.json', [])).slice(0, 200) });
  }

  if (pathname === '/api/searches/clear' && isDel) {
    const s = requireAdmin(req, res); if (!s) return;
    await writeJson('searches.json', []);
    await addLog('Admin', 'Search analytics wiped', 'Success');
    return json(res, 200, { searches: [] });
  }

  // ================= LOGS =================
  if (pathname === '/api/logs' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    return json(res, 200, { logs: (await readJson('logs.json', [])).slice(0, 300) });
  }

  if (pathname === '/api/logs/clear' && isDel) {
    const s = requireAdmin(req, res); if (!s) return;
    await writeJson('logs.json', []);
    await addLog('System', 'Audit logs purged by Admin', 'Warning');
    return json(res, 200, { logs: [] });
  }

  // ================= ADMIN: users =================
  if (pathname === '/api/admin/users' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    const users = await readJson('users.json', []);
    return json(res, 200, { users: users.map(sanitizeUser) });
  }

  if (seg[0] === 'api' && seg[1] === 'admin' && seg[2] === 'users' && seg[3] && isDel) {
    const s = requireAdmin(req, res); if (!s) return;
    const id = seg[3];
    const users = await readJson('users.json', []);
    const idx = users.findIndex(u => u.id === id);
    if (idx === -1) return json(res, 404, { error: 'User not found.' });
    const name = users[idx].name;
    users.splice(idx, 1);
    await writeJson('users.json', users);
    const lib = await readJson('library.json', {});
    const pl = await readJson('playlists.json', {});
    delete lib[id]; delete pl[id];
    await writeJson('library.json', lib);
    await writeJson('playlists.json', pl);
    await addLog('User Purge', 'Admin purged account for: ' + name, 'Deleted');
    return json(res, 200, { ok: true });
  }

  // ================= ADMIN: settings =================
  if (pathname === '/api/settings' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    return json(res, 200, {
      settings: {
        banner: settings.banner,
        apiKeys: settings.apiKeys,
        palette: settings.palette
        // admin passcode is NEVER returned — only settable
      }
    });
  }

  if (pathname === '/api/settings' && isPost) {
    const s = requireAdmin(req, res); if (!s) return;
    if (typeof body.banner === 'string') settings.banner = body.banner.trim().slice(0, 300);
    if (Array.isArray(body.apiKeys)) {
      settings.apiKeys = body.apiKeys.map(k => String(k).trim()).filter(k => k.length > 8).slice(0, 40);
    }
    if (body.palette && typeof body.palette === 'object') {
      const p = body.palette;
      settings.palette = {
        pink: String(p.pink || settings.palette.pink).slice(0, 30),
        purple: String(p.purple || settings.palette.purple).slice(0, 30),
        bg: String(p.bg || settings.palette.bg).slice(0, 30),
        card: String(p.card || settings.palette.card).slice(0, 30)
      };
    }
    if (body.newPasscode && String(body.newPasscode).length >= 4) {
      settings.adminPassSalt = makeSalt();
      settings.adminPassHash = hashPassword(String(body.newPasscode), settings.adminPassSalt);
      await addLog('Security', 'Admin passcode updated', 'Success');
    }
    await saveSettings();
    await addLog('Admin', 'Site settings updated', 'Success');
    return json(res, 200, { ok: true });
  }

  // ================= ADMIN: palette =================
  if (pathname === '/api/palette' && isPost) {
    const s = requireAdmin(req, res); if (!s) return;
    const p = body.palette || body;
    settings.palette = {
      pink: String(p.pink || settings.palette.pink).slice(0, 30),
      purple: String(p.purple || settings.palette.purple).slice(0, 30),
      bg: String(p.bg || settings.palette.bg).slice(0, 30),
      card: String(p.card || settings.palette.card).slice(0, 30)
    };
    await saveSettings();
    await addLog('Theme', 'Updated custom color palette', 'Success');
    return json(res, 200, { ok: true });
  }

  // ================= ADMIN: backup & restore =================
  if (pathname === '/api/backup' && isGet) {
    const s = requireAdmin(req, res); if (!s) return;
    const data = {
      tracks: await readJson('tracks.json', []),
      users: await readJson('users.json', []),
      inbox: await readJson('inbox.json', []),
      searches: await readJson('searches.json', []),
      logs: await readJson('logs.json', []),
      library: await readJson('library.json', {}),
      playlists: await readJson('playlists.json', {}),
      palette: settings.palette,
      banner: settings.banner,
      apiKeys: settings.apiKeys,
      exportedAt: new Date().toISOString()
    };
    await addLog('Backup', 'Exported complete database archive', 'Success');
    return json(res, 200, data);
  }

  if (pathname === '/api/restore' && isPost) {
    const s = requireAdmin(req, res); if (!s) return;
    const d = body.data || body;
    if (!d || typeof d !== 'object') return json(res, 400, { error: 'Invalid backup data.' });
    const safewrite = (key, arr) => Array.isArray(arr) || typeof arr === 'object'
      ? writeJson(key + '.json', arr) : Promise.resolve();
    await Promise.all([
      safewrite('tracks', d.tracks),
      safewrite('users', d.users),
      safewrite('inbox', d.inbox),
      safewrite('searches', d.searches),
      safewrite('logs', d.logs),
      safewrite('library', d.library),
      safewrite('playlists', d.playlists)
    ]);
    if (d.palette && typeof d.palette === 'object') settings.palette = d.palette;
    if (typeof d.banner === 'string') settings.banner = d.banner;
    if (Array.isArray(d.apiKeys)) settings.apiKeys = d.apiKeys.filter(k => String(k).length > 8).slice(0, 40);
    await saveSettings();
    await addLog('Backup', 'Restored master database from backup', 'Success');
    return json(res, 200, { ok: true });
  }

  // ================= SEARCH / DOWNLOAD / LYRICS PROXIES =================
  if (pathname === '/api/search' && isGet) {
    const q = query.get('q');
    if (!q) return json(res, 400, { error: 'Missing query.' });
    try {
      const data = await apiSearch(q);
      return json(res, 200, data);
    } catch (e) {
      return json(res, 502, { error: 'Search engine unavailable. Try again later.' });
    }
  }

  if (pathname === '/api/download' && isGet) {
    const id = query.get('id');
    if (!id || id.startsWith('z')) return json(res, 400, { error: 'Invalid track id.' });
    try {
      const link = await apiDownloadLink(id);
      if (!link) return json(res, 502, { error: 'Could not locate a download link for this track.' });
      return json(res, 200, { link });
    } catch (e) {
      return json(res, 502, { error: 'API limit reached or track unavailable.' });
    }
  }

  if (pathname === '/api/lyrics' && isGet) {
    const q = query.get('q');
    if (!q) return json(res, 400, { error: 'Missing query.' });
    try {
      const data = await apiLyrics(q);
      return json(res, 200, data);
    } catch (e) {
      return json(res, 502, { error: 'Lyrics service unavailable.' });
    }
  }

  if (pathname === '/api/stream' && isGet) {
    const url = query.get('url');
    if (!url || !/^https?:\/\//i.test(url)) return json(res, 400, { error: 'Invalid stream URL.' });
    try {
      const upstream = await fetchUpstream(url, {}, 60000);
      if (upstream.statusCode !== 200) {
        upstream.resume();
        return json(res, 502, { error: 'Audio source returned ' + upstream.statusCode });
      }
      res.writeHead(200, {
        'Content-Type': upstream.headers['content-type'] || 'audio/mpeg',
        'Content-Length': upstream.headers['content-length'],
        'Cache-Control': 'no-store',
        'Accept-Ranges': 'bytes'
      });
      upstream.pipe(res);
      upstream.on('error', () => { try { res.end(); } catch (e) {} });
    } catch (e) {
      return json(res, 502, { error: 'Failed to stream audio.' });
    }
    return; // response handled by pipe
  }

  return json(res, 404, { error: 'Endpoint not found.' });
}

// ------------------------------------------------------------------
// Static file serving
// ------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.webmanifest': 'application/manifest+json'
};

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  let filePath = path.normalize(path.join(STATIC_DIR, rel));
  if (!filePath.startsWith(STATIC_DIR)) {
    res.writeHead(403); return res.end('Forbidden');
  }
  // Block serving the data/ directory and server internals
  const lower = filePath.toLowerCase();
  if (lower.includes(path.sep + 'data' + path.sep) || lower.endsWith(path.sep + 'data')) {
    res.writeHead(403); return res.end('Forbidden');
  }
  if (path.basename(filePath) === 'server.js' || path.basename(filePath) === 'package.json') {
    res.writeHead(403); return res.end('Forbidden');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Try index.html of folder
      const idx = path.join(filePath, 'index.html');
      fs.stat(idx, (err2, s2) => {
        if (err2 || !s2.isFile()) {
          res.writeHead(404); return res.end('Not Found');
        }
        const ext = path.extname(idx).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        fs.createReadStream(idx).pipe(res);
      });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });
}

// ------------------------------------------------------------------
// Main server
// ------------------------------------------------------------------
async function main() {
  await ensureDataDir();
  await loadSettings();
  await loadSessions();

  const server = http.createServer(async (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const parsed = new URL(req.url, 'http://localhost');
    const pathname = decodeURIComponent(parsed.pathname);
    const query = parsed.searchParams;

    // Security headers for every response
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');

    if (pathname.startsWith('/api/')) {
      const body = (req.method === 'POST' || req.method === 'PUT') ? await readBody(req) : {};
      try {
        await handleApi(req, res, pathname, query, body, ip);
      } catch (e) {
        console.error('[ZoneVaz API error]', e);
        if (!res.headersSent) json(res, 500, { error: 'Internal server error.' });
      }
      return;
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      serveStatic(req, res, pathname);
    } else {
      res.writeHead(405); res.end('Method Not Allowed');
    }
  });

  const PORT = process.env.PORT || 8080;
  server.listen(PORT, () => {
    console.log('✨ ZoneVaz Studio is live:  http://localhost:' + PORT);
    console.log('   Data directory: ' + DATA_DIR);
  });
}

main().catch(e => {
  console.error('Fatal startup error:', e);
  process.exit(1);
});
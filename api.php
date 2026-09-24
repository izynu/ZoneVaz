<?php
/* ============================================================
   ZoneVaz Studio — PHP Secure Backend (works on ANY shared cPanel)
   ------------------------------------------------------------
   Handles every /api/* route used by the ZoneVaz front-end:
   auth, sessions, CSRF, per-user library/playlists, admin panel,
   RapidAPI search/download/lyrics proxies, MP3 streaming, backup.
   Data stored in ./data as JSON files (auto-created, writable).
   ============================================================ */

error_reporting(E_ERROR);
ini_set('display_errors', '0');

/* mbstring fallbacks (some shared hosts disable mbstring) */
if (!function_exists('mb_strlen')) { function mb_strlen($s, $e = null) { return strlen($s); } }
if (!function_exists('mb_substr')) { function mb_substr($s, $a, $l = null, $e = null) { return ($l === null) ? substr($s, $a) : substr($s, $a, $l); } }

define('DATA_DIR', __DIR__ . '/data');

/* ---------------- Bootstrap --------------- */
if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0755, true);
    @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\n");
}

/* ---------------- Sessions (secure) ---------------- */
// Keep server-side session data alive for 30 days (supports "Remember me")
@ini_set('session.gc_maxlifetime', 30 * 24 * 3600);
$secureCookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
if (function_exists('session_set_cookie_params')) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secureCookie,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}
session_name('zv_sid');
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ---------------- Helpers ---------------- */
function respond($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function respondError($msg, $code = 400) {
    respond(['error' => $msg], $code);
}
function getBody() {
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $d = json_decode($raw, true);
    return is_array($d) ? $d : [];
}
function loadJson($file, $fallback) {
    $p = DATA_DIR . '/' . $file;
    if (!file_exists($p)) return $fallback;
    $raw = @file_get_contents($p);
    if ($raw === false) return $fallback;
    $d = json_decode($raw, true);
    return ($d === null) ? $fallback : $d;
}
function saveJson($file, $data) {
    return @file_put_contents(DATA_DIR . '/' . $file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}
function addLog($category, $details, $status = 'Success') {
    $logs = loadJson('logs.json', []);
    array_unshift($logs, [
        'id'        => 'log_' . time() . '_' . substr(bin2hex(random_bytes(4)), 0, 6),
        'timestamp' => date('n/j/Y, g:i:s A'),
        'category'  => (string)$category,
        'details'   => (string)$details,
        'status'    => (string)$status
    ]);
    saveJson('logs.json', array_slice($logs, 0, 300));
}

/* ---------------- Settings ---------------- */
$settings = loadJson('settings.json', null);
if (!$settings || !isset($settings['adminPassHash'])) {
    $settings = [
        'adminPassHash' => password_hash('zynu2026', PASSWORD_BCRYPT),
        'banner'        => '',
        'apiKeys'       => [
            '18ec28704fmsh289906a33589844p13ddd7jsn4faff9883a7d',
            '8a59f4306dmsh406b4268969c6dep14656djsnc11d8f7f4852',
            '250d9a4280mshd3898b43c92a32bp15c7ecjsn05e64955903c',
            'afc0e0f25fmsh982b1ec63cc3355p1b1cfcjsndfcb3e981190',
            '76a7c31a63mshc69bdd7f44458f4p1fd655jsneb626c23425a'
        ],
        'palette'       => ['pink' => '#ff9ebd', 'purple' => '#c49fff', 'bg' => '#0c0511', 'card' => '#130919']
    ];
    saveJson('settings.json', $settings);
}
$settings['banner']  = isset($settings['banner']) ? (string)$settings['banner'] : '';
$settings['apiKeys'] = isset($settings['apiKeys']) && is_array($settings['apiKeys']) ? array_values(array_filter($settings['apiKeys'])) : [];
$settings['palette'] = isset($settings['palette']) && is_array($settings['palette']) ? $settings['palette'] : ['pink' => '#ff9ebd', 'purple' => '#c49fff', 'bg' => '#0c0511', 'card' => '#130919'];

function saveSettings() {
    global $settings;
    saveJson('settings.json', $settings);
}

/* ---------------- Auth helpers ---------------- */
function currentUser() {
    if (empty($_SESSION['userId'])) return null;
    $users = loadJson('users.json', []);
    foreach ($users as $u) {
        if (isset($u['id']) && $u['id'] === $_SESSION['userId']) return $u;
    }
    return null;
}
function requireUser() {
    $u = currentUser();
    if (!$u) respondError('Please login first.', 401);
    return $u;
}
function isAdmin() {
    return !empty($_SESSION['isAdmin']);
}
function requireAdmin() {
    if (!isAdmin()) respondError('Admin access required.', 403);
}
/* ---- Role-based permissions ---- */
function hasPerm($perm) {
    if (empty($_SESSION['isAdmin'])) return false;
    if (!empty($_SESSION['isSuper'])) return true;
    $perms = isset($_SESSION['perms']) && is_array($_SESSION['perms']) ? $_SESSION['perms'] : [];
    return in_array($perm, $perms, true);
}
function requirePerm($perm) {
    if (!hasPerm($perm)) respondError('You do not have permission for this section.', 403);
}
function adminInfo() {
    if (empty($_SESSION['isAdmin'])) return null;
    if (!empty($_SESSION['isSuper'])) {
        return [
            'id'         => 'super',
            'name'       => 'Zynu',
            'email'      => 'zynu@zonevaz.me',
            'isSuper'    => true,
            'permissions'=> ['*'],
            'isZoneEmail'=> true
        ];
    }
    $admins = loadJson('admins.json', []);
    foreach ($admins as $a) {
        if (isset($a['id']) && $a['id'] === $_SESSION['adminId']) {
            return [
                'id'         => $a['id'],
                'name'       => isset($a['name']) ? $a['name'] : '',
                'email'      => isset($a['email']) ? $a['email'] : '',
                'isSuper'    => false,
                'permissions'=> isset($a['permissions']) && is_array($a['permissions']) ? $a['permissions'] : [],
                'isZoneEmail'=> !empty($a['isZoneEmail'])
            ];
        }
    }
    return null;
}
function csrfOk($body = []) {
    $tok = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
    if ($tok === '' && is_array($body) && isset($body['_csrf'])) $tok = $body['_csrf'];
    if ($tok === '' && isset($_GET['_csrf'])) $tok = $_GET['_csrf'];
    return $tok !== '' && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $tok);
}

/* ---------------- Rate limiting (per IP) ---------------- */
function checkRate($key, $limit = 10) {
    $file = DATA_DIR . '/rate.json';
    $map  = file_exists($file) ? json_decode(@file_get_contents($file), true) : [];
    if (!is_array($map)) $map = [];
    $now = time();
    foreach ($map as $k => $v) {
        if (!isset($v['reset']) || $v['reset'] < $now) unset($map[$k]);
    }
    $id = ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . ':' . $key;
    if (!isset($map[$id])) $map[$id] = ['count' => 0, 'reset' => $now + 300];
    $map[$id]['count']++;
    @file_put_contents($file, json_encode($map), LOCK_EX);
    return $map[$id]['count'] <= $limit;
}

/* Extend the session cookie to 30 days when "Remember me" is ticked */
function applyRemember($remember) {
    if (!$remember) return;
    // Rotate the session id (fixation protection)
    session_regenerate_id(true);
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
    $lifetime = 30 * 24 * 3600;
    // Re-issue the session cookie with a long Max-Age (the last Set-Cookie wins in browsers)
    $cookie = session_name() . '=' . session_id();
    $cookie .= '; Path=/';
    $cookie .= '; Max-Age=' . $lifetime;
    $cookie .= '; Expires=' . gmdate('D, d M Y H:i:s', time() + $lifetime) . ' GMT';
    if ($secure) $cookie .= '; Secure';
    $cookie .= '; HttpOnly; SameSite=Strict';
    header('Set-Cookie: ' . $cookie, false);
}

/* ---------------- Upstream HTTP (cURL) ---------------- */
function curlGet($url, $headers = [], $timeout = 20) {
    if (!function_exists('curl_init')) {
        // cURL missing — try allow_url_fopen stream
        $ctx = stream_context_create(['http' => ['timeout' => $timeout, 'header' => implode("\r\n", $headers) . "\r\n", 'ignore_errors' => true]]);
        return [@file_get_contents($url, false, $ctx), 200];
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER     => $headers
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$body, $code];
}

/* ---------- Rate-limited key skip list (daily rotation) ---------- */
function loadSkipList() {
    return loadJson('ratelimit.json', []);
}
function saveSkipList($s) {
    saveJson('ratelimit.json', $s);
}
function endOfDayUtc() {
    return strtotime('tomorrow 00:00:00 UTC');
}

/* Single-key RapidAPI request; throws 'ratelimited' on 429/403 */
function rapidApiGetKey($endpoint, $query, $key) {
    $url = 'https://spotify-downloader9.p.rapidapi.com/' . $endpoint . '?' . $query;
    list($body, $code) = curlGet($url, [
        'x-rapidapi-host: spotify-downloader9.p.rapidapi.com',
        'x-rapidapi-key: ' . $key
    ]);
    if ($code === 429 || $code === 403) throw new Exception('ratelimited');
    if ($code !== 200) throw new Exception('status ' . $code);
    $data = json_decode($body, true);
    if (!is_array($data)) throw new Exception('bad response');
    return $data;
}

/* Returns shuffled key order that excludes currently-skipped keys */
function rotateKeys() {
    global $settings;
    $keys = $settings['apiKeys'];
    shuffle($keys);
    $skip = loadSkipList();
    $now = time();
    foreach ($skip as $k => $t) { if ($t < $now) unset($skip[$k]); }
    $order = [];
    foreach ($keys as $k) { if (!isset($skip[$k])) $order[] = $k; }
    return [$order, $skip];
}

/* Auto-rotating request: tries random keys, skips exhausted ones for the day */
function rapidApiGetRotate($endpoint, $query) {
    list($order, $skip) = rotateKeys();
    $lastErr = null;
    foreach ($order as $key) {
        try {
            return rapidApiGetKey($endpoint, $query, $key);
        } catch (Exception $e) {
            if ($e->getMessage() === 'ratelimited') {
                $skip[$key] = endOfDayUtc(); // exhausted until tomorrow
            }
            $lastErr = $e;
        }
    }
    saveSkipList($skip);
    throw $lastErr ?: new Exception('No keys available.');
}

function apiSearch($q) {
    return rapidApiGetRotate('search', 'q=' . urlencode($q) . '&type=tracks');
}
function apiDownloadLink($trackId) {
    $data = rapidApiGetRotate('downloadSong', 'songId=' . urlencode('https://open.spotify.com/track/' . $trackId));
    $link = null;
    if (isset($data['data']) && is_array($data['data'])) {
        $link = $data['data']['downloadLink'] ?? ($data['data']['link'] ?? null);
    }
    if (!$link) $link = $data['downloadLink'] ?? ($data['link'] ?? null);
    return $link;
}
function apiLyrics($q) {
    list($body, $code) = curlGet('https://lrclib.net/api/search?q=' . urlencode($q));
    if ($code !== 200 || !$body) throw new Exception('lyrics failed');
    $d = json_decode($body, true);
    return is_array($d) ? $d : [];
}

/* ---------- Per-user usage / quota / history ---------- */
function todayKey() {
    return gmdate('Y-m-d');
}
function loadUsage() {
    return loadJson('usage.json', []);
}
function saveUsage($u) {
    saveJson('usage.json', $u);
}
function getDailyCount($identity) {
    $usage = loadUsage();
    $day = todayKey();
    return isset($usage[$day][$identity]) ? (int)$usage[$day][$identity] : 0;
}
function addDailyUse($identity) {
    $usage = loadUsage();
    $day = todayKey();
    if (!isset($usage[$day])) $usage[$day] = [];
    if (!isset($usage[$day][$identity])) $usage[$day][$identity] = 0;
    $usage[$day][$identity]++;
    // keep only the last 3 days
    $keys = array_keys($usage);
    if (count($keys) > 3) {
        sort($keys);
        while (count($keys) > 3) unset($usage[array_shift($keys)]);
    }
    saveUsage($usage);
}
function recordHistory($identity, $trackId, $title, $artist) {
    $h = loadJson('history.json', []);
    if (!isset($h[$identity])) $h[$identity] = [];
    array_unshift($h[$identity], [
        'date'   => date('n/j/Y, g:i:s A'),
        'trackId' => (string)$trackId,
        'title'  => mb_substr((string)$title, 0, 200, 'UTF-8'),
        'artist' => mb_substr((string)$artist, 0, 200, 'UTF-8')
    ]);
    $h[$identity] = array_slice($h[$identity], 0, 50);
    saveJson('history.json', $h);
}
function generateUserKey() {
    return 'zv_' . bin2hex(random_bytes(16));
}

/* Resolve who is downloading: session user > presented vibe key > anonymous IP */
function resolveDownloadIdentity() {
    $u = currentUser();
    if ($u) {
        return [
            'identity' => $u['id'],
            'limit'    => 20,
            'loggedIn' => true,
            'isUser'   => true
        ];
    }
    $qkey = isset($_GET['key']) ? trim((string)$_GET['key']) : '';
    if ($qkey !== '') {
        $users = loadJson('users.json', []);
        foreach ($users as $x) {
            if (!empty($x['apiKey']) && hash_equals($x['apiKey'], $qkey)) {
                return [
                    'identity' => $x['id'],
                    'limit'    => 20,
                    'loggedIn' => false,
                    'isUser'   => true
                ];
            }
        }
    }
    return [
        'identity' => isset($_SERVER['REMOTE_ADDR']) ? 'ip_' . $_SERVER['REMOTE_ADDR'] : 'ip_unknown',
        'limit'    => 3,
        'loggedIn' => false,
        'isUser'   => false
    ];
}

/* ---------- Album-cover extraction from search results ---------- */
function findCover($track) {
    if (!is_array($track)) return '';
    foreach (['images', 'image', 'artwork', 'cover', 'thumbnail'] as $k) {
        if (isset($track[$k])) {
            $v = $track[$k];
            if (is_array($v)) {
                foreach ($v as $item) {
                    if (is_array($item) && isset($item['url']) && is_string($item['url'])) return $item['url'];
                    if (is_string($item) && preg_match('#^https?://#i', $item)) return $item;
                }
            } elseif (is_string($v) && preg_match('#^https?://#i', $v)) return $v;
        }
    }
    if (isset($track['album']) && is_array($track['album'])) return findCover($track['album']);
    return '';
}
function addCovers($obj) {
    $found = false;
    $walk = function (&$node) use (&$walk, &$found) {
        if ($found) return;
        if (is_array($node)) {
            if (!empty($node) && is_array($node[0]) &&
                (isset($node[0]['name']) || isset($node[0]['title'])) &&
                (isset($node[0]['id']) || isset($node[0]['uri']))) {
                foreach ($node as &$t) {
                    if (is_array($t) && !isset($t['cover'])) $t['cover'] = findCover($t);
                }
                $found = true;
                return;
            }
            foreach ($node as &$child) { $walk($child); if ($found) return; }
        }
    };
    $copy = $obj;
    $walk($copy);
    return $copy;
}

function sanitizeUser($u) {
    if (!is_array($u)) return null;
    return [
        'id'           => isset($u['id']) ? $u['id'] : '',
        'name'         => isset($u['name']) ? $u['name'] : '',
        'email'        => isset($u['email']) ? $u['email'] : '',
        'avatar'       => isset($u['avatar']) ? $u['avatar'] : '☁️',
        'registeredAt' => isset($u['registeredAt']) ? $u['registeredAt'] : 'Prior Member'
    ];
}

/* ============================================================
   ROUTER
   ============================================================ */
$uri  = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
$path = parse_url($uri, PHP_URL_PATH);
if ($path === false) $path = '/';
$pos  = strpos($path, '/api');
$route = $pos !== false ? substr($path, $pos) : $path;
$seg = array_values(array_filter(explode('/', $route), function ($s) { return $s !== ''; }));
// $seg[0] === 'api'

$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';

/* Handle CORS preflight (OPTIONS) gracefully — some hosts reject it otherwise */
if ($method === 'OPTIONS') {
    http_response_code(204);
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, X-Requested-With');
    header('Access-Control-Max-Age: 86400');
    exit;
}

$body = getBody();
$isPost = $method === 'POST';
$isPut  = $method === 'PUT'    || ($isPost && isset($body['_method']) && $body['_method'] === 'PUT');
$isDel  = $method === 'DELETE' || ($isPost && isset($body['_method']) && $body['_method'] === 'DELETE');

/* CSRF guard for state-changing requests */
if ($isPost || $isPut || $isDel) {
    if (!csrfOk($body)) respondError('Invalid session token. Refresh the page and try again.', 403);
}

if (empty($seg[0]) || $seg[0] !== 'api') {
    respondError('Not found', 404);
}
$ep = isset($seg[1]) ? $seg[1] : '';

/* ============ BOOTSTRAP ============ */
if ($ep === 'bootstrap') {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(18));
    $user = currentUser();
    respond([
        'user'    => $user ? sanitizeUser($user) : null,
        'isAdmin' => isAdmin(),
        'admin'   => adminInfo(),
        'csrf'    => $_SESSION['csrf'],
        'config'  => [
            'banner'  => $settings['banner'],
            'palette' => $settings['palette']
        ]
    ]);
}

/* ============ AUTH ============ */
if ($ep === 'register' && $isPost) {
    if (!checkRate('register')) respondError('Too many attempts. Wait a few minutes.', 429);
    $b = $body;
    $name  = trim(isset($b['name']) ? (string)$b['name'] : '');
    $email = strtolower(trim(isset($b['email']) ? (string)$b['email'] : ''));
    $pass  = (string)(isset($b['pass']) ? $b['pass'] : '');
    $avatar = trim(isset($b['avatar']) ? (string)$b['avatar'] : '☁️');
    if (!$name || !$email || !$pass) respondError('Please fill all fields!', 400);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) respondError('Please enter a valid email address.', 400);
    if (strlen($pass) < 6) respondError('Password must be at least 6 characters long.', 400);
    if (mb_strlen($name, 'UTF-8') > 40) respondError('Name is too long.', 400);
    $users = loadJson('users.json', []);
    foreach ($users as $u) {
        if (isset($u['email']) && $u['email'] === $email) respondError('An account with this email already exists!', 409);
    }
    $newUser = [
        'id'           => 'u_' . time() . '_' . bin2hex(random_bytes(4)),
        'name'         => $name,
        'email'        => $email,
        'passHash'     => password_hash($pass, PASSWORD_BCRYPT),
        'avatar'       => $avatar,
        'apiKey'       => generateUserKey(),
        'registeredAt' => date('n/j/Y')
    ];
    $users[] = $newUser;
    saveJson('users.json', $users);
    $_SESSION['userId'] = $newUser['id']; // reuse same session → CSRF stays valid
    applyRemember(!empty($b['remember']));
    addLog('Registration', 'New audiophile joined: ' . $name . ' (' . $email . ')', 'Registered');
    respond(['user' => sanitizeUser($newUser)]);
}

if ($ep === 'login' && $isPost) {
    if (!checkRate('login')) respondError('Too many attempts. Wait a few minutes.', 429);
    $b = $body;
    $email = strtolower(trim(isset($b['email']) ? (string)$b['email'] : ''));
    $pass  = (string)(isset($b['pass']) ? $b['pass'] : '');
    $users = loadJson('users.json', []);
    $found = null;
    foreach ($users as $u) {
        if (isset($u['email']) && $u['email'] === $email) { $found = $u; break; }
    }
    if (!$found || !isset($found['passHash']) || !password_verify($pass, $found['passHash'])) {
        addLog('Security', 'Failed sign-in attempt for email: "' . $email . '"', 'Blocked');
        respondError('Invalid email or password!', 401);
    }
    $_SESSION['userId'] = $found['id'];
    applyRemember(!empty($b['remember']));
    addLog('Auth', 'User signed in: ' . $found['name'] . ' (' . $email . ')', 'Success');
    respond(['user' => sanitizeUser($found)]);
}

if ($ep === 'logout' && $isPost) {
    $_SESSION = [];
    session_destroy();
    respond(['ok' => true]);
}

if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'login' && $isPost) {
    if (!checkRate('admin')) respondError('Too many attempts. Wait a few minutes.', 429);
    $b = $body;

    // Option 1: MASTER PASSCODE → Super Admin (Zynu)
    if (isset($b['passcode']) && trim((string)$b['passcode']) !== '') {
        $pass = (string)$b['passcode'];
        if (!password_verify($pass, $settings['adminPassHash'])) {
            addLog('Security Alert', 'Failed admin login attempt', 'Blocked');
            respondError('Access Denied: Invalid Passcode!', 401);
        }
        $_SESSION['isAdmin']  = true;
        $_SESSION['isSuper']  = true;
        unset($_SESSION['adminId'], $_SESSION['perms']);
        addLog('Admin Gate', 'Super Admin unlocked the Studio', 'Success');
        respond(['ok' => true, 'admin' => adminInfo()]);
    }

    // Option 2: ADMIN EMAIL + PASSWORD → sub-admin with permissions
    $email = strtolower(trim(isset($b['email']) ? (string)$b['email'] : ''));
    $pass  = (string)(isset($b['pass']) ? $b['pass'] : '');
    $admins = loadJson('admins.json', []);
    foreach ($admins as $a) {
        if (isset($a['email']) && strtolower($a['email']) === $email) {
            if (!isset($a['passHash']) || !password_verify($pass, $a['passHash'])) {
                addLog('Security Alert', 'Failed admin login for: ' . $email, 'Blocked');
                respondError('Invalid email or password!', 401);
            }
            $_SESSION['isAdmin']  = true;
            $_SESSION['isSuper']  = false;
            $_SESSION['adminId']  = $a['id'];
            $_SESSION['perms']    = isset($a['permissions']) && is_array($a['permissions']) ? $a['permissions'] : [];
            addLog('Admin Gate', 'Admin signed in: ' . (isset($a['name']) ? $a['name'] : $email), 'Success');
            respond(['ok' => true, 'admin' => adminInfo()]);
        }
    }
    addLog('Security Alert', 'Unknown admin email attempted login: ' . $email, 'Blocked');
    respondError('Invalid email or password!', 401);
}

/* ============ ADMIN: TEAM MANAGEMENT (Super Admin only) ============ */
if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'team' && !isset($seg[3]) && $method === 'GET') {
    requirePerm('admins');
    $admins = loadJson('admins.json', []);
    $list = [];
    foreach ($admins as $a) {
        $list[] = [
            'id'          => $a['id'],
            'name'        => isset($a['name']) ? $a['name'] : '',
            'email'       => isset($a['email']) ? $a['email'] : '',
            'permissions' => isset($a['permissions']) && is_array($a['permissions']) ? $a['permissions'] : [],
            'isZoneEmail' => !empty($a['isZoneEmail']),
            'createdAt'   => isset($a['createdAt']) ? $a['createdAt'] : 'Recent'
        ];
    }
    respond(['admins' => $list, 'permOptions' => [
        'tracks'   => 'Tracks (upload / edit / delete)',
        'users'    => 'Site Users',
        'inbox'    => 'Fan Requests / Inbox',
        'searches' => 'Search Analytics',
        'theme'    => 'Color & Vibe Studio',
        'logs'     => 'Activity Logs',
        'settings' => 'Site & Passcode Settings',
        'backup'   => 'Backup & Restore'
    ]]);
}

if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'team' && !isset($seg[3]) && $isPost) {
    requirePerm('admins');
    $b = $body;
    $name = trim(isset($b['name']) ? (string)$b['name'] : '');
    $email = strtolower(trim(isset($b['email']) ? (string)$b['email'] : ''));
    $pass = (string)(isset($b['pass']) ? $b['pass'] : '');
    $perms = isset($b['permissions']) && is_array($b['permissions']) ? array_values(array_filter($b['permissions'], 'is_string')) : [];

    // ZoneEmail: auto-generate name@zonevaz.me
    if (!empty($b['makeZoneEmail'])) {
        $zone = strtolower(preg_replace('/[^a-z0-9._-]/i', '', str_replace(' ', '.', $name)));
        if ($zone === '') $zone = 'member' . rand(100, 999);
        $email = $zone . '@zonevaz.me';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) respondError('Please enter a valid email.', 400);
    if ($name === '') respondError('Please enter a name.', 400);
    if (strlen($pass) < 6) respondError('Password must be at least 6 characters.', 400);

    $admins = loadJson('admins.json', []);
    foreach ($admins as $a) {
        if (isset($a['email']) && strtolower($a['email']) === $email) respondError('An admin with this email already exists!', 409);
    }
    $admins[] = [
        'id'          => 'a_' . time() . '_' . bin2hex(random_bytes(4)),
        'name'        => $name,
        'email'       => $email,
        'passHash'    => password_hash($pass, PASSWORD_BCRYPT),
        'permissions' => $perms,
        'isZoneEmail' => !empty($b['makeZoneEmail']),
        'createdAt'   => date('n/j/Y')
    ];
    saveJson('admins.json', $admins);
    addLog('Admin Team', 'Created admin: ' . $name . ' (' . $email . ')', 'Created');
    respond(['ok' => true]);
}

if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'team' && isset($seg[3]) && ($isPut || $isDel)) {
    requirePerm('admins');
    $id = $seg[3];
    $admins = loadJson('admins.json', []);
    $idx = -1;
    foreach ($admins as $i => $a) { if ($a['id'] === $id) { $idx = $i; break; } }
    if ($idx === -1) respondError('Admin not found.', 404);

    if ($isDel) {
        $name = $admins[$idx]['name'];
        array_splice($admins, $idx, 1);
        saveJson('admins.json', $admins);
        addLog('Admin Team', 'Deleted admin: ' . $name, 'Deleted');
        respond(['ok' => true]);
    }

    $b = $body;
    if (isset($b['name']) && trim((string)$b['name']) !== '') $admins[$idx]['name'] = trim((string)$b['name']);
    if (isset($b['email']) && trim((string)$b['email']) !== '') {
        $email = strtolower(trim((string)$b['email']));
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            foreach ($admins as $i2 => $a2) {
                if ($i2 !== $idx && isset($a2['email']) && strtolower($a2['email']) === $email) respondError('Email already used by another admin.', 409);
            }
            $admins[$idx]['email'] = $email;
        }
    }
    if (isset($b['permissions']) && is_array($b['permissions'])) $admins[$idx]['permissions'] = array_values(array_filter($b['permissions'], 'is_string'));
    if (isset($b['pass']) && trim((string)$b['pass']) !== '') {
        if (strlen((string)$b['pass']) < 6) respondError('Password must be at least 6 characters.', 400);
        $admins[$idx]['passHash'] = password_hash((string)$b['pass'], PASSWORD_BCRYPT);
    }
    saveJson('admins.json', $admins);
    addLog('Admin Team', 'Updated admin: ' . $admins[$idx]['name'], 'Updated');
    respond(['ok' => true]);
}

/* ============ ADMIN: CHANGE OWN PASSWORD ============ */
if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'password' && $isPost) {
    if (!isAdmin()) respondError('Admin access required.', 403);
    $b = $body;
    $oldPass = (string)(isset($b['oldPass']) ? $b['oldPass'] : '');
    $newPass = (string)(isset($b['newPass']) ? $b['newPass'] : '');
    if (strlen($newPass) < 6) respondError('New password must be at least 6 characters.', 400);

    if (!empty($_SESSION['isSuper'])) {
        // Super admin → update the master passcode
        if (!password_verify($oldPass, $settings['adminPassHash'])) respondError('Incorrect current passcode.', 403);
        $settings['adminPassHash'] = password_hash($newPass, PASSWORD_BCRYPT);
        saveSettings();
        addLog('Security', 'Super Admin changed the master passcode', 'Success');
    } else {
        $admins = loadJson('admins.json', []);
        $idx = -1;
        foreach ($admins as $i => $a) { if ($a['id'] === $_SESSION['adminId']) { $idx = $i; break; } }
        if ($idx === -1) respondError('Admin not found.', 404);
        if (!isset($admins[$idx]['passHash']) || !password_verify($oldPass, $admins[$idx]['passHash'])) respondError('Incorrect current password.', 403);
        $admins[$idx]['passHash'] = password_hash($newPass, PASSWORD_BCRYPT);
        saveJson('admins.json', $admins);
        addLog('Security', 'Admin changed own password: ' . $admins[$idx]['name'], 'Success');
    }
    respond(['ok' => true]);
}

/* ============ PROFILE ============ */
if ($ep === 'profile' && !isset($seg[2]) && $isPost) {
    $u = requireUser();
    $users = loadJson('users.json', []);
    $idx = -1;
    foreach ($users as $i => $x) { if ($x['id'] === $u['id']) { $idx = $i; break; } }
    if ($idx === -1) respondError('User not found.', 404);
    $b = $body;
    if (isset($b['name']) && is_string($b['name'])) {
        $name = trim($b['name']);
        if ($name === '' || mb_strlen($name, 'UTF-8') > 40) respondError('Name cannot be empty or too long!', 400);
        $users[$idx]['name'] = $name;
    }
    if (isset($b['avatar']) && is_string($b['avatar'])) {
        if (strlen($b['avatar']) > 2 * 1024 * 1024) respondError('Avatar image too large.', 400);
        $users[$idx]['avatar'] = $b['avatar'];
    }
    saveJson('users.json', $users);
    addLog('Profile Update', 'User updated profile: ' . $users[$idx]['name'], 'Success');
    respond(['user' => sanitizeUser($users[$idx])]);
}

if ($ep === 'profile' && isset($seg[2]) && $seg[2] === 'security' && $isPost) {
    $u = requireUser();
    $users = loadJson('users.json', []);
    $idx = -1;
    foreach ($users as $i => $x) { if ($x['id'] === $u['id']) { $idx = $i; break; } }
    if ($idx === -1) respondError('User not found.', 404);
    $b = $body;
    $oldPass = (string)(isset($b['oldPass']) ? $b['oldPass'] : '');
    if (!isset($users[$idx]['passHash']) || !password_verify($oldPass, $users[$idx]['passHash'])) {
        respondError('Incorrect current password.', 403);
    }
    if (isset($b['newEmail'])) {
        $email = strtolower(trim((string)$b['newEmail']));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) respondError('Invalid email address.', 400);
        foreach ($users as $x) {
            if (isset($x['email']) && $x['email'] === $email && $x['id'] !== $u['id']) respondError('This email is already in use.', 409);
        }
        $users[$idx]['email'] = $email;
    }
    if (isset($b['newPass'])) {
        if (strlen((string)$b['newPass']) < 6) respondError('New password must be at least 6 characters.', 400);
        $users[$idx]['passHash'] = password_hash((string)$b['newPass'], PASSWORD_BCRYPT);
    }
    saveJson('users.json', $users);
    addLog('Security', 'User updated credentials: ' . $users[$idx]['name'], 'Success');
    respond(['ok' => true]);
}

if ($ep === 'profile' && isset($seg[2]) && $seg[2] === 'delete' && $isPost) {
    $u = requireUser();
    $users = loadJson('users.json', []);
    $idx = -1;
    foreach ($users as $i => $x) { if ($x['id'] === $u['id']) { $idx = $i; break; } }
    if ($idx === -1) respondError('User not found.', 404);
    $name = $users[$idx]['name'];
    array_splice($users, $idx, 1);
    saveJson('users.json', $users);
    $lib = loadJson('library.json', []);
    $pl  = loadJson('playlists.json', []);
    unset($lib[$u['id']], $pl[$u['id']]);
    saveJson('library.json', $lib);
    saveJson('playlists.json', $pl);
    addLog('User Deletion', 'User self-deleted account: ' . $name, 'Warning');
    $_SESSION = [];
    session_destroy();
    respond(['ok' => true]);
}

/* ============ USER VIBE KEY / QUOTA / HISTORY ============ */
if ($ep === 'mykey' && $method === 'GET') {
    $u = requireUser();
    if (empty($u['apiKey'])) {
        // migrate legacy accounts: give them a key
        $users = loadJson('users.json', []);
        foreach ($users as $i => $x) { if ($x['id'] === $u['id']) { $users[$i]['apiKey'] = generateUserKey(); break; } }
        saveJson('users.json', $users);
        $u = currentUser();
    }
    $used = getDailyCount($u['id']);
    respond([
        'key'       => $u['apiKey'],
        'limit'     => 20,
        'used'      => $used,
        'remaining' => max(0, 20 - $used)
    ]);
}

if ($ep === 'regenerate' && isset($seg[2]) && $seg[2] === 'key' && $isPost) {
    $u = requireUser();
    $users = loadJson('users.json', []);
    foreach ($users as $i => $x) { if ($x['id'] === $u['id']) { $users[$i]['apiKey'] = generateUserKey(); break; } }
    saveJson('users.json', $users);
    $u = currentUser();
    addLog('Security', 'User regenerated their Vibe Key: ' . $u['name'], 'Success');
    $used = getDailyCount($u['id']);
    respond([
        'key'       => $u['apiKey'],
        'limit'     => 20,
        'used'      => $used,
        'remaining' => max(0, 20 - $used)
    ]);
}

if ($ep === 'quota' && $method === 'GET') {
    // Resolve identity exactly like downloads so the panel matches reality
    $resolved = resolveDownloadIdentity();
    $limit = $resolved['limit'];
    $used  = getDailyCount($resolved['identity']);
    respond([
        'limit'     => $limit,
        'used'      => $used,
        'remaining' => max(0, $limit - $used),
        'loggedIn'  => $resolved['loggedIn'],
        'isUser'    => $resolved['isUser']
    ]);
}

if ($ep === 'history' && $method === 'GET') {
    $u = requireUser();
    $h = loadJson('history.json', []);
    respond(['history' => isset($h[$u['id']]) ? $h[$u['id']] : []]);
}
if ($ep === 'history' && isset($seg[2]) && $seg[2] === 'clear' && $isDel) {
    $u = requireUser();
    $h = loadJson('history.json', []);
    $h[$u['id']] = [];
    saveJson('history.json', $h);
    respond(['history' => []]);
}

/* ============ TRACKS ============ */
if ($ep === 'tracks' && !isset($seg[2]) && $method === 'GET') {
    respond(['tracks' => loadJson('tracks.json', [])]);
}

if ($ep === 'tracks' && !isset($seg[2]) && $isPost) {
    requirePerm('tracks');
    $b = $body;
    $track = isset($b['track']) && is_array($b['track']) ? $b['track'] : $b;
    $title = trim(isset($track['title']) ? (string)$track['title'] : '');
    if ($title === '') respondError('Title is mandatory!', 400);
    $newTrack = [
        'id'       => 'z' . time(),
        'title'    => $title,
        'artist'   => trim(isset($track['artist']) ? (string)$track['artist'] : '') !== '' ? trim((string)$track['artist']) : 'Zynu',
        'tag'      => trim(isset($track['tag']) ? (string)$track['tag'] : '') !== '' ? trim((string)$track['tag']) : 'Original',
        'details'  => trim(isset($track['details']) ? (string)$track['details'] : ''),
        'cover'    => isset($track['cover']) ? (string)$track['cover'] : '',
        'audioUrl' => isset($track['audioUrl']) ? (string)$track['audioUrl'] : '',
        'pinned'   => !empty($track['pinned']),
        'links'    => [
            'spotify'    => trim(isset($track['links']['spotify']) ? (string)$track['links']['spotify'] : ''),
            'youtube'    => trim(isset($track['links']['youtube']) ? (string)$track['links']['youtube'] : ''),
            'apple'      => trim(isset($track['links']['apple']) ? (string)$track['links']['apple'] : ''),
            'soundcloud' => trim(isset($track['links']['soundcloud']) ? (string)$track['links']['soundcloud'] : '')
        ]
    ];
    $tracks = loadJson('tracks.json', []);
    array_unshift($tracks, $newTrack);
    saveJson('tracks.json', $tracks);
    addLog('Track', 'Published new original track: "' . $title . '"', 'Created');
    respond(['track' => $newTrack]);
}

if ($ep === 'tracks' && isset($seg[2]) && ($isPut || $isDel)) {
    requirePerm('tracks');
    $id = $seg[2];
    $tracks = loadJson('tracks.json', []);
    $idx = -1;
    foreach ($tracks as $i => $t) { if ($t['id'] === $id) { $idx = $i; break; } }
    if ($idx === -1) respondError('Track not found.', 404);
    if ($isDel) {
        $title = $tracks[$idx]['title'];
        array_splice($tracks, $idx, 1);
        saveJson('tracks.json', $tracks);
        addLog('Track', 'Deleted track: "' . $title . '"', 'Deleted');
        respond(['ok' => true]);
    }
    $b = $body;
    $track = isset($b['track']) && is_array($b['track']) ? $b['track'] : $b;
    $title = trim(isset($track['title']) ? (string)$track['title'] : '');
    if ($title === '') respondError('Title is mandatory!', 400);
    $old = $tracks[$idx];
    $tracks[$idx]['title']    = $title;
    $tracks[$idx]['artist']   = trim(isset($track['artist']) ? (string)$track['artist'] : '') !== '' ? trim((string)$track['artist']) : (isset($old['artist']) ? $old['artist'] : 'Zynu');
    $tracks[$idx]['tag']      = trim(isset($track['tag']) ? (string)$track['tag'] : '') !== '' ? trim((string)$track['tag']) : 'Original';
    $tracks[$idx]['details']  = trim(isset($track['details']) ? (string)$track['details'] : '');
    if (isset($track['cover']) && is_string($track['cover'])) $tracks[$idx]['cover'] = $track['cover'];
    if (isset($track['audioUrl']) && is_string($track['audioUrl'])) $tracks[$idx]['audioUrl'] = $track['audioUrl'];
    $tracks[$idx]['pinned']   = !empty($track['pinned']);
    $tracks[$idx]['links']    = [
        'spotify'    => trim(isset($track['links']['spotify']) ? (string)$track['links']['spotify'] : ''),
        'youtube'    => trim(isset($track['links']['youtube']) ? (string)$track['links']['youtube'] : ''),
        'apple'      => trim(isset($track['links']['apple']) ? (string)$track['links']['apple'] : ''),
        'soundcloud' => trim(isset($track['links']['soundcloud']) ? (string)$track['links']['soundcloud'] : '')
    ];
    saveJson('tracks.json', $tracks);
    addLog('Track', 'Updated details for track: "' . $title . '"', 'Updated');
    respond(['track' => $tracks[$idx]]);
}

/* ============ LIBRARY (per-user) ============ */
if ($ep === 'library' && !isset($seg[2]) && $method === 'GET') {
    $u = requireUser();
    $lib = loadJson('library.json', []);
    respond(['library' => isset($lib[$u['id']]) ? $lib[$u['id']] : []]);
}
if ($ep === 'library' && !isset($seg[2]) && $isPost) {
    $u = requireUser();
    $b = $body;
    $trackId = (string)(isset($b['trackId']) ? $b['trackId'] : '');
    $title   = mb_substr(trim(isset($b['title']) ? (string)$b['title'] : ''), 0, 200, 'UTF-8');
    $artist  = mb_substr(trim(isset($b['artist']) ? (string)$b['artist'] : ''), 0, 200, 'UTF-8');
    if ($trackId === '') respondError('Missing track.', 400);
    $lib = loadJson('library.json', []);
    $arr = isset($lib[$u['id']]) ? $lib[$u['id']] : [];
    $found = -1;
    foreach ($arr as $i => $t) { if ($t['trackId'] === $trackId) { $found = $i; break; } }
    if ($found === -1) {
        array_unshift($arr, ['trackId' => $trackId, 'title' => $title, 'artist' => $artist, 'addedAt' => time()]);
        $added = true;
    } else {
        array_splice($arr, $found, 1);
        $added = false;
    }
    $arr = array_slice($arr, 0, 500);
    $lib[$u['id']] = $arr;
    saveJson('library.json', $lib);
    respond(['library' => $arr, 'added' => $added]);
}

/* ============ PLAYLISTS (per-user) ============ */
if ($ep === 'playlists' && !isset($seg[2]) && $method === 'GET') {
    $u = requireUser();
    $all = loadJson('playlists.json', []);
    respond(['playlists' => isset($all[$u['id']]) ? $all[$u['id']] : []]);
}
if ($ep === 'playlists' && !isset($seg[2]) && $isPost) {
    $u = requireUser();
    $b = $body;
    $name = mb_substr(trim(isset($b['name']) ? (string)$b['name'] : ''), 0, 80, 'UTF-8');
    if ($name === '') respondError('Please enter a playlist name!', 400);
    $all = loadJson('playlists.json', []);
    $arr = isset($all[$u['id']]) ? $all[$u['id']] : [];
    array_unshift($arr, ['id' => 'pl_' . time() . '_' . bin2hex(random_bytes(3)), 'name' => $name, 'tracks' => []]);
    $all[$u['id']] = array_slice($arr, 0, 200);
    saveJson('playlists.json', $all);
    respond(['playlists' => $all[$u['id']]]);
}
if ($ep === 'playlists' && isset($seg[2]) && !isset($seg[3]) && $isDel) {
    // Delete an ENTIRE playlist (only when no extra segments follow, e.g. /tracks/:id)
    $u = requireUser();
    $all = loadJson('playlists.json', []);
    $arr = isset($all[$u['id']]) ? $all[$u['id']] : [];
    $out = [];
    foreach ($arr as $p) { if ($p['id'] !== $seg[2]) $out[] = $p; }
    $all[$u['id']] = $out;
    saveJson('playlists.json', $all);
    respond(['playlists' => $out]);
}
if ($ep === 'playlists' && isset($seg[2]) && !isset($seg[3]) && $isPut) {
    // Rename a playlist
    $u = requireUser();
    $b = $body;
    $name = mb_substr(trim(isset($b['name']) ? (string)$b['name'] : ''), 0, 80, 'UTF-8');
    if ($name === '') respondError('Please enter a playlist name!', 400);
    $all = loadJson('playlists.json', []);
    $arr = isset($all[$u['id']]) ? $all[$u['id']] : [];
    $found = false;
    foreach ($arr as $i => $p) {
        if ($p['id'] === $seg[2]) { $arr[$i]['name'] = $name; $found = true; break; }
    }
    if (!$found) respondError('Playlist not found.', 404);
    $all[$u['id']] = $arr;
    saveJson('playlists.json', $all);
    respond(['playlists' => $arr]);
}
if ($ep === 'playlists' && isset($seg[2]) && isset($seg[3]) && $seg[3] === 'tracks' && $isPost && !$isPut && !$isDel) {
    // Add a track to a playlist (plain POST only — not a PUT/DELETE override)
    $u = requireUser();
    $b = $body;
    $all = loadJson('playlists.json', []);
    $arr = isset($all[$u['id']]) ? $all[$u['id']] : [];
    $plIdx = -1;
    foreach ($arr as $i => $p) { if ($p['id'] === $seg[2]) { $plIdx = $i; break; } }
    if ($plIdx === -1) respondError('Playlist not found.', 404);
    $trackId = (string)(isset($b['trackId']) ? $b['trackId'] : '');
    $already = false;
    foreach ($arr[$plIdx]['tracks'] as $t) { if ($t['trackId'] === $trackId) { $already = true; break; } }
    if (!$already) {
        $arr[$plIdx]['tracks'][] = [
            'trackId' => $trackId,
            'title'   => mb_substr(isset($b['title']) ? (string)$b['title'] : '', 0, 200, 'UTF-8'),
            'artist'  => mb_substr(isset($b['artist']) ? (string)$b['artist'] : '', 0, 200, 'UTF-8')
        ];
        $all[$u['id']] = $arr; // write the modified array back into the saved map
        saveJson('playlists.json', $all);
    }
    respond(['playlists' => $arr]);
}
if ($ep === 'playlists' && isset($seg[2]) && isset($seg[3]) && $seg[3] === 'tracks' && isset($seg[4]) && $isDel) {
    $u = requireUser();
    $all = loadJson('playlists.json', []);
    $arr = isset($all[$u['id']]) ? $all[$u['id']] : [];
    $plIdx = -1;
    foreach ($arr as $i => $p) { if ($p['id'] === $seg[2]) { $plIdx = $i; break; } }
    if ($plIdx !== -1) {
        $out = [];
        foreach ($arr[$plIdx]['tracks'] as $t) { if ($t['trackId'] !== $seg[4]) $out[] = $t; }
        $arr[$plIdx]['tracks'] = $out;
        $all[$u['id']] = $arr; // write the modified array back into the saved map
        saveJson('playlists.json', $all);
    }
    respond(['playlists' => $arr]);
}

/* ============ REQUESTS / INBOX ============ */
if ($ep === 'requests' && !isset($seg[2]) && $isPost) {
    $u = requireUser();
    $b = $body;
    $title = mb_substr(trim(isset($b['songTitle']) ? (string)$b['songTitle'] : (isset($b['title']) ? (string)$b['title'] : '')), 0, 200, 'UTF-8');
    $note  = mb_substr(trim(isset($b['note']) ? (string)$b['note'] : ''), 0, 2000, 'UTF-8');
    if ($title === '') respondError('Please enter a song title or vibe!', 400);
    $inbox = loadJson('inbox.json', []);
    array_unshift($inbox, ['date' => date('n/j/Y'), 'sender' => $u['name'], 'songTitle' => $title, 'note' => $note]);
    saveJson('inbox.json', array_slice($inbox, 0, 500));
    respond(['ok' => true]);
}
if ($ep === 'requests' && !isset($seg[2]) && $method === 'GET') {
    requirePerm('inbox');
    respond(['inbox' => loadJson('inbox.json', [])]);
}
if ($ep === 'requests' && isset($seg[2]) && $seg[2] === 'clear' && $isDel) {
    requirePerm('inbox');
    saveJson('inbox.json', []);
    addLog('Admin', 'Inbox cleared', 'Success');
    respond(['inbox' => []]);
}
if ($ep === 'requests' && isset($seg[2]) && $seg[2] === 'replace' && $isPost) {
    requirePerm('inbox');
    $b = $body;
    $inbox = isset($b['inbox']) && is_array($b['inbox']) ? array_slice($b['inbox'], 0, 500) : [];
    saveJson('inbox.json', $inbox);
    respond(['inbox' => $inbox]);
}

/* ============ SEARCHES ============ */
if ($ep === 'searches' && $isPost) {
    $b = $body;
    $q = mb_substr(trim(isset($b['query']) ? (string)$b['query'] : ''), 0, 200, 'UTF-8');
    if ($q !== '') {
        $searches = loadJson('searches.json', []);
        array_unshift($searches, ['time' => date('n/j/Y, g:i:s A'), 'query' => $q]);
        saveJson('searches.json', array_slice($searches, 0, 300));
    }
    respond(['ok' => true]);
}
if ($ep === 'searches' && !isset($seg[2]) && $method === 'GET') {
    requirePerm('searches');
    respond(['searches' => array_slice(loadJson('searches.json', []), 0, 200)]);
}
if ($ep === 'searches' && isset($seg[2]) && $seg[2] === 'clear' && $isDel) {
    requirePerm('searches');
    saveJson('searches.json', []);
    addLog('Admin', 'Search analytics wiped', 'Success');
    respond(['searches' => []]);
}

/* ============ LOGS ============ */
if ($ep === 'logs' && !isset($seg[2]) && $method === 'GET') {
    requirePerm('logs');
    respond(['logs' => array_slice(loadJson('logs.json', []), 0, 300)]);
}
if ($ep === 'logs' && isset($seg[2]) && $seg[2] === 'clear' && $isDel) {
    requirePerm('logs');
    saveJson('logs.json', []);
    addLog('System', 'Audit logs purged by Admin', 'Warning');
    respond(['logs' => []]);
}

/* ============ ADMIN: users ============ */
if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'users' && $method === 'GET') {
    requirePerm('users');
    $users = loadJson('users.json', []);
    respond(['users' => array_map('sanitizeUser', $users)]);
}
if ($ep === 'admin' && isset($seg[2]) && $seg[2] === 'users' && isset($seg[3]) && $isDel) {
    requirePerm('users');
    $id = $seg[3];
    $users = loadJson('users.json', []);
    $idx = -1;
    foreach ($users as $i => $u) { if ($u['id'] === $id) { $idx = $i; break; } }
    if ($idx === -1) respondError('User not found.', 404);
    $name = $users[$idx]['name'];
    array_splice($users, $idx, 1);
    saveJson('users.json', $users);
    $lib = loadJson('library.json', []);
    $pl  = loadJson('playlists.json', []);
    unset($lib[$id], $pl[$id]);
    saveJson('library.json', $lib);
    saveJson('playlists.json', $pl);
    addLog('User Purge', 'Admin purged account for: ' . $name, 'Deleted');
    respond(['ok' => true]);
}

/* ============ ADMIN: settings ============ */
if ($ep === 'settings' && $method === 'GET') {
    requirePerm('settings');
    respond(['settings' => [
        'banner'  => $settings['banner'],
        'apiKeys' => $settings['apiKeys'],
        'palette' => $settings['palette']
    ]]);
}
if ($ep === 'settings' && $isPost) {
    requirePerm('settings');
    $b = $body;
    if (isset($b['banner']) && is_string($b['banner'])) $settings['banner'] = mb_substr(trim($b['banner']), 0, 300, 'UTF-8');
    if (isset($b['apiKeys']) && is_array($b['apiKeys'])) {
        $keys = [];
        foreach ($b['apiKeys'] as $k) {
            $k = trim((string)$k);
            if (strlen($k) > 8) $keys[] = $k;
        }
        $settings['apiKeys'] = array_slice($keys, 0, 40);
    }
    if (isset($b['palette']) && is_array($b['palette'])) {
        $p = $b['palette'];
        $settings['palette'] = [
            'pink'   => isset($p['pink'])   ? mb_substr((string)$p['pink'], 0, 30, 'UTF-8')   : $settings['palette']['pink'],
            'purple' => isset($p['purple']) ? mb_substr((string)$p['purple'], 0, 30, 'UTF-8') : $settings['palette']['purple'],
            'bg'     => isset($p['bg'])     ? mb_substr((string)$p['bg'], 0, 30, 'UTF-8')     : $settings['palette']['bg'],
            'card'   => isset($p['card'])   ? mb_substr((string)$p['card'], 0, 30, 'UTF-8')   : $settings['palette']['card']
        ];
    }
    if (isset($b['newPasscode']) && strlen((string)$b['newPasscode']) >= 4) {
        $settings['adminPassHash'] = password_hash((string)$b['newPasscode'], PASSWORD_BCRYPT);
        addLog('Security', 'Admin passcode updated', 'Success');
    }
    saveSettings();
    addLog('Admin', 'Site settings updated', 'Success');
    respond(['ok' => true]);
}

/* ============ ADMIN: palette ============ */
if ($ep === 'palette' && $isPost) {
    requirePerm('theme');
    $b = $body;
    $p = isset($b['palette']) && is_array($b['palette']) ? $b['palette'] : $b;
    $settings['palette'] = [
        'pink'   => isset($p['pink'])   ? mb_substr((string)$p['pink'], 0, 30, 'UTF-8')   : $settings['palette']['pink'],
        'purple' => isset($p['purple']) ? mb_substr((string)$p['purple'], 0, 30, 'UTF-8') : $settings['palette']['purple'],
        'bg'     => isset($p['bg'])     ? mb_substr((string)$p['bg'], 0, 30, 'UTF-8')     : $settings['palette']['bg'],
        'card'   => isset($p['card'])   ? mb_substr((string)$p['card'], 0, 30, 'UTF-8')   : $settings['palette']['card']
    ];
    saveSettings();
    addLog('Theme', 'Updated custom color palette', 'Success');
    respond(['ok' => true]);
}

/* ============ ADMIN: backup / restore ============ */
if ($ep === 'backup' && $method === 'GET') {
    requirePerm('backup');
    respond([
        'tracks'     => loadJson('tracks.json', []),
        'users'      => loadJson('users.json', []),
        'inbox'      => loadJson('inbox.json', []),
        'searches'   => loadJson('searches.json', []),
        'logs'       => loadJson('logs.json', []),
        'library'    => loadJson('library.json', []),
        'playlists'  => loadJson('playlists.json', []),
        'history'    => loadJson('history.json', []),
        'palette'    => $settings['palette'],
        'banner'     => $settings['banner'],
        'apiKeys'    => $settings['apiKeys'],
        'exportedAt' => date('c')
    ]);
}
if ($ep === 'restore' && $isPost) {
    requirePerm('backup');
    $b = $body;
    $d = isset($b['data']) && is_array($b['data']) ? $b['data'] : $b;
    if (!is_array($d)) respondError('Invalid backup data.', 400);
    if (isset($d['tracks']))    saveJson('tracks.json', $d['tracks']);
    if (isset($d['users']))     saveJson('users.json', $d['users']);
    if (isset($d['inbox']))     saveJson('inbox.json', $d['inbox']);
    if (isset($d['searches']))  saveJson('searches.json', $d['searches']);
    if (isset($d['logs']))      saveJson('logs.json', $d['logs']);
    if (isset($d['library']))   saveJson('library.json', $d['library']);
    if (isset($d['playlists'])) saveJson('playlists.json', $d['playlists']);
    if (isset($d['history']))   saveJson('history.json', $d['history']);
    if (isset($d['palette']) && is_array($d['palette'])) $settings['palette'] = $d['palette'];
    if (isset($d['banner']) && is_string($d['banner'])) $settings['banner'] = $d['banner'];
    if (isset($d['apiKeys']) && is_array($d['apiKeys'])) {
        $keys = [];
        foreach ($d['apiKeys'] as $k) { $k = trim((string)$k); if (strlen($k) > 8) $keys[] = $k; }
        $settings['apiKeys'] = array_slice($keys, 0, 40);
    }
    saveSettings();
    addLog('Backup', 'Restored master database from backup', 'Success');
    respond(['ok' => true]);
}

/* ============ PROXIES: search / download / lyrics ============ */
if ($ep === 'search' && $method === 'GET') {
    $q = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
    if ($q === '') respondError('Missing query.', 400);
    try {
        $data = apiSearch($q);
        respond(addCovers($data)); // attach album-cover URLs for the IG story
    } catch (Exception $e) {
        respondError('Search engine unavailable. Try again later.', 502);
    }
}

if ($ep === 'download' && $method === 'GET') {
    $id = isset($_GET['id']) ? (string)$_GET['id'] : '';
    if ($id === '' || strpos($id, 'z') === 0) respondError('Invalid track id.', 400);

    // Who is downloading + quota
    $r = resolveDownloadIdentity();
    $used = getDailyCount($r['identity']);
    $remaining = max(0, $r['limit'] - $used);
    if ($used >= $r['limit']) {
        respondError(
            $r['isUser']
                ? 'Daily download limit reached (' . $r['limit'] . '/day). It resets tomorrow — enjoy your vibes!'
                : 'Guest limit reached (3 downloads/day). Log in for 20 downloads every day!',
            429
        );
    }

    try {
        $link = apiDownloadLink($id);
        if (!$link) respondError('Could not locate a download link for this track. Try again later.', 502);
        addDailyUse($r['identity']);
        $title = isset($_GET['title']) ? (string)$_GET['title'] : 'Track';
        $artist = isset($_GET['artist']) ? (string)$_GET['artist'] : 'Artist';
        if ($r['isUser']) recordHistory($r['identity'], $id, $title, $artist);
        respond([
            'link'      => $link,
            'remaining' => max(0, $remaining - 1),
            'limit'     => $r['limit'],
            'loggedIn'  => $r['loggedIn']
        ]);
    } catch (Exception $e) {
        respondError('All download sources are busy right now. Please try again in a few minutes.', 502);
    }
}

if ($ep === 'lyrics' && $method === 'GET') {
    $q = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
    if ($q === '') respondError('Missing query.', 400);
    try {
        respond(apiLyrics($q));
    } catch (Exception $e) {
        respondError('Lyrics service unavailable.', 502);
    }
}

/* ============ PROXY: MP3 streaming ============ */
if ($ep === 'stream' && $method === 'GET') {
    $url = isset($_GET['url']) ? (string)$_GET['url'] : '';
    if (!preg_match('#^https?://#i', $url)) respondError('Invalid stream URL.', 400);
    set_time_limit(120);
    @ini_set('zlib.output_compression', '0');
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: audio/mpeg');
    header('Cache-Control: no-store');
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FAILONERROR    => true,
            CURLOPT_TIMEOUT        => 100,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_WRITEFUNCTION  => function ($ch, $data) {
                echo $data;
                @ob_flush();
                @flush();
                return strlen($data);
            }
        ]);
        $ok = curl_exec($ch);
        curl_close($ch);
        if ($ok === false) { http_response_code(502); echo 'Stream failed'; }
        exit;
    }
    // No cURL fallback: readfile with context
    $ctx = stream_context_create(['http' => ['timeout' => 100, 'ignore_errors' => true]]);
    $fp = @fopen($url, 'rb', false, $ctx);
    if ($fp === false) { http_response_code(502); echo 'Stream failed'; exit; }
    while (!feof($fp)) { echo fread($fp, 65536); @ob_flush(); @flush(); }
    fclose($fp);
    exit;
}

respondError('Endpoint not found.', 404);
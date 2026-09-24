/* ============================================================
   ZoneVaz common.js — shared safe client helpers
   • esc()          : HTML-escape user content (XSS-safe)
   • ZV.api()       : fetch wrapper (JSON + CSRF header)
   • ZV.bootstrap() : loads session/config, applies palette+banner
   • ZV.safeGet()   : crash-proof localStorage reads
   ============================================================ */
(function () {
    var _csrf = null;
    var _boot = null;

    function esc(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/`/g, '&#96;');
    }

    function safeGet(key, fallback) {
        try {
            var raw = localStorage.getItem(key);
            if (raw === null || raw === undefined) return fallback;
            return JSON.parse(raw);
        } catch (e) {
            return fallback;
        }
    }

    function safeSet(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); }
        catch (e) { /* ignore quota/private-mode errors */ }
    }

    function applyPalette(palette) {
        if (!palette) return;
        var root = document.documentElement.style;
        root.setProperty('--cute-pink', palette.pink || '#ff9ebd');
        root.setProperty('--cute-purple', palette.purple || '#c49fff');
        root.setProperty('--bg-dark', palette.bg || '#0c0511');
        root.setProperty('--card-bg', palette.card || '#130919');
        // cache for instant paint on next page load
        safeSet('zonevaz_palette_cache', palette);
    }

    function applyBanner(text) {
        var b = document.getElementById('topBanner');
        if (!b) return;
        if (text) {
            b.innerText = text;
            b.style.display = 'block';
        } else {
            b.style.display = 'none';
        }
    }

    var DEFAULT_PALETTE = { pink: '#ff9ebd', purple: '#c49fff', bg: '#0c0511', card: '#130919' };

    function isCustomPalette(p) {
        if (!p) return false;
        return !!(p.pink !== DEFAULT_PALETTE.pink || p.purple !== DEFAULT_PALETTE.purple ||
                  p.bg !== DEFAULT_PALETTE.bg || p.card !== DEFAULT_PALETTE.card);
    }

    function getSavedTheme() {
        try { return localStorage.getItem('zonevaz_theme') || ''; } catch (e) { return ''; }
    }

    /* Sync the saved theme (cyber / sakura / default) to EVERY page */
    function applyTheme(palette) {
        var theme = getSavedTheme();
        document.body.classList.remove('theme-cyber', 'theme-sakura');
        if (theme === 'theme-cyber' || theme === 'theme-sakura') {
            if (!isCustomPalette(palette)) document.body.classList.add(theme);
        }
    }

    async function bootstrap() {
        if (_boot) return _boot;
        try {
            var r = await fetch('/api/bootstrap', { credentials: 'same-origin' });
            var data = await r.json();
            _boot = data;
            _csrf = data.csrf || null;
            if (data.config) {
                if (data.config.palette) applyPalette(data.config.palette);
                applyBanner(data.config.banner);
                applyTheme(data.config.palette);
            }
            return data;
        } catch (e) {
            console.warn('ZoneVaz: bootstrap failed (server offline?).', e);
            var cached = safeGet('zonevaz_palette_cache', null);
            if (cached) applyPalette(cached);
            applyTheme(cached);
            return { user: null, isAdmin: false, csrf: null, config: {} };
        }
    }

    async function api(path, opts) {
        opts = opts || {};
        var method = (opts.method || 'GET').toUpperCase();

        // IMPORTANT: this site's host blocks browser CORS preflight (OPTIONS),
        // so we avoid it entirely:
        //  • no custom headers
        //  • writes are always POST, signaling PUT/DELETE via _method in the body
        //  • the CSRF token travels inside the JSON body (_csrf), not a header
        //  • Content-Type is text/plain (a "simple" content type → no preflight)
        var realMethod = method;
        var body = opts.body;
        if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = opts.body; } }
        if (realMethod === 'GET') {
            body = undefined;
        } else {
            if (body === undefined || body === null) body = {};
            if (realMethod === 'PUT' || realMethod === 'DELETE') {
                body._method = realMethod;
                realMethod = 'POST';
            }
            body._csrf = _csrf;
        }

        var r = await fetch(path, {
            method: realMethod,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
            credentials: 'same-origin',
            body: body !== undefined ? JSON.stringify(body) : undefined
        });
        var data = null;
        try { data = await r.json(); } catch (e) { data = null; }
        if (!r.ok) {
            var msg = (data && data.error) ? data.error : ('Request failed (' + r.status + ')');
            var err = new Error(msg);
            err.status = r.status;
            throw err;
        }
        return data;
    }

    async function logout() {
        try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
        window.location.reload();
    }

    /* Copy text with a temporary input fallback (works on any browser) */
    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return false; });
        }
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            var ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return Promise.resolve(ok);
        } catch (e) {
            return Promise.resolve(false);
        }
    }

    window.ZV = {
        esc: esc,
        safeGet: safeGet,
        safeSet: safeSet,
        applyPalette: applyPalette,
        applyBanner: applyBanner,
        applyTheme: applyTheme,
        isCustomPalette: isCustomPalette,
        bootstrap: bootstrap,
        api: api,
        logout: logout,
        copyText: copyText
    };
})();
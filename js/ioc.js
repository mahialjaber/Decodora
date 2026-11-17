/*
 * Decodora IOC extractor.
 *
 * Pulls indicators of compromise (URLs, domains, IPv4s, emails, hashes, CVEs)
 * out of decoded text and produces safe, defanged copies for tickets and chat.
 *
 * Pure logic: no DOM access, no network access. Works in the browser
 * (window.DecodoraIOC) and in Node.js (module.exports) for testing.
 */
(function (root) {
  'use strict';

  // Real-world TLDs we accept for bare domains. File extensions that collide with
  // TLDs (.ps1, .exe, .sh, .py, .md, .zip, .mov ...) are deliberately left out so
  // script/file names inside decoded payloads are not reported as domains.
  const TLDS = new Set((
    'com net org edu gov mil int info biz name pro mobi asia ' +
    'io co ai app dev cloud online site website space tech store shop live link click ' +
    'xyz top icu buzz club fun work today life world email network digital solutions services ' +
    'support help center host page win bid loan download stream review ' +
    'ru su cn hk tw jp kr in id vn th my sg ph pk bd ir iq tr sa ae il ' +
    'uk de fr nl be ch at it es pt se no fi dk ie eu pl cz sk hu ro bg gr ua by kz lt lv ee ' +
    'us ca mx br ar cl pe ve au nz za ng ke eg ma ' +
    'me tv cc ws la to gg im ly gd tk ml ga cf gq pw nu fm am ' +
    'onion test example invalid localhost'
  ).split(/\s+/));

  // Redirect/wrapper infrastructure: still reported, but tagged so analysts
  // don't block Microsoft or Proofpoint by accident.
  const WRAPPER_HOSTS = /(?:^|\.)(?:safelinks\.protection\.outlook\.com|urldefense(?:\.proofpoint)?\.com)$/i;

  const TYPE_ORDER = ['URL', 'Domain', 'IPv4', 'Email', 'SHA256', 'SHA1', 'MD5', 'CVE'];

  /* ------------------------------------------------------------------ */
  /* Re-fang / defang                                                   */
  /* ------------------------------------------------------------------ */

  function refang(text) {
    return String(text)
      .replace(/\bhxxp(s?)(?=\[?:|:\/\/)/gi, 'http$1')
      .replace(/\bfxp(?=\[?:|:\/\/)/gi, 'ftp')
      .replace(/\[\s*:\s*\/\s*\/\s*\]/g, '://')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}/gi, '.')
      .replace(/\[\s*(?:@|at)\s*\]/gi, '@');
  }

  function defangHost(host) {
    return host.replace(/\./g, '[.]');
  }

  function defangScheme(scheme) {
    return scheme.toLowerCase().replace(/^http/, 'hxxp').replace(/^ftp/, 'fxp') + '[:]//';
  }

  function defangAuthority(authority) {
    return authority.replace(/@/g, '[@]').replace(/\./g, '[.]');
  }

  function defangUrl(url) {
    const m = url.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i);
    if (!m) return defangHost(url);
    // Also neutralise URLs nested in the query string (redirect wrappers), so no part stays clickable.
    const rest = m[3].replace(/\b(https?|ftp):\/\/([^/?#&\s]*)/gi, function (_, s, a) {
      return defangScheme(s) + defangAuthority(a);
    }).replace(/[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}/g, defangEmail);
    return defangScheme(m[1]) + defangAuthority(m[2]) + rest;
  }

  function defangEmail(email) {
    const at = email.lastIndexOf('@');
    return email.slice(0, at) + '[@]' + defangHost(email.slice(at + 1));
  }

  function defangValue(type, value) {
    if (type === 'URL') return defangUrl(value);
    if (type === 'Email') return defangEmail(value);
    if (type === 'Domain' || type === 'IPv4') return defangHost(value);
    return value;
  }

  /* ------------------------------------------------------------------ */
  /* Classification helpers                                             */
  /* ------------------------------------------------------------------ */

  function validTld(host) {
    const tld = host.slice(host.lastIndexOf('.') + 1).toLowerCase();
    return TLDS.has(tld);
  }

  function ipNote(ip) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)) return 'private';
    if (p[0] === 127) return 'loopback';
    if (p[0] === 169 && p[1] === 254) return 'link-local';
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'CGNAT';
    if (p[0] === 0) return 'reserved';
    if (p[0] >= 224) return p[0] < 240 ? 'multicast' : 'reserved';
    return '';
  }

  function isIpv4(s) {
    return /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s);
  }

  // Bare dotted tokens that are really .NET / PowerShell type names.
  function looksLikeCodeIdentifier(token) {
    return /^(?:System|Microsoft\.(?:Win32|PowerShell|VisualBasic|CSharp))\./.test(token);
  }

  function trimUrl(url) {
    let u = url;
    for (;;) {
      const last = u.slice(-1);
      if (/[.,;:!?'"`>\]}]/.test(last)) { u = u.slice(0, -1); continue; }
      if (last === ')' && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) { u = u.slice(0, -1); continue; }
      break;
    }
    return u;
  }

  function urlHost(url) {
    const m = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
    if (!m) return '';
    let host = m[1];
    const at = host.lastIndexOf('@');
    if (at !== -1) host = host.slice(at + 1);
    host = host.replace(/:\d+$/, '');
    return host.toLowerCase();
  }

  /* ------------------------------------------------------------------ */
  /* Extraction                                                         */
  /* ------------------------------------------------------------------ */

  const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>`^{}|\\]+/gi;
  const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])/g;
  const DOMAIN_RE = /(?<![A-Za-z0-9_@.$-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])/g;
  const IPV4_RE = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d|\.\d)/g;
  const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
  const HASH_RES = [
    ['SHA256', /(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])/g],
    ['SHA1', /(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])/g],
    ['MD5', /(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])/g]
  ];

  /**
   * Extract indicators from text.
   * @param {string} text
   * @returns {{type:string, value:string, defanged:string, note:string}[]}
   */
  function extract(text) {
    if (typeof text !== 'string' || text.trim() === '') return [];
    const src = refang(text);
    const seen = new Set();
    const items = [];

    function add(type, value, note) {
      const key = type + '|' + (type === 'Domain' || type === 'Email' ? value.toLowerCase() : value);
      if (seen.has(key)) return;
      seen.add(key);
      items.push({ type: type, value: value, defanged: defangValue(type, value), note: note || '' });
    }

    function addHost(host) {
      if (!host) return;
      if (isIpv4(host)) add('IPv4', host, ipNote(host));
      else if (host.includes('.') && validTld(host)) add('Domain', host, WRAPPER_HOSTS.test(host) ? 'wrapper' : '');
    }

    for (const m of src.matchAll(URL_RE)) {
      const url = trimUrl(m[0]);
      const host = urlHost(url);
      if (!host) continue;
      add('URL', url, WRAPPER_HOSTS.test(host) ? 'wrapper' : '');
      addHost(host);
      // "https://login.microsoftonline.com@203.0.113.47/" -> the part before "@" is a lure, not the host.
      const auth = (url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i) || [])[1] || '';
      const at = auth.lastIndexOf('@');
      if (at > 0) {
        const lure = auth.slice(0, at).replace(/:.*$/, '').toLowerCase();
        if (lure.includes('.') && validTld(lure) && !isIpv4(lure)) add('Domain', lure, 'lure (@ userinfo)');
      }
    }

    for (const m of src.matchAll(EMAIL_RE)) {
      const email = m[0];
      if (validTld(email)) add('Email', email, '');
    }

    for (const m of src.matchAll(DOMAIN_RE)) {
      const token = m[0];
      if (isIpv4(token) || looksLikeCodeIdentifier(token)) continue;
      addHost(token.toLowerCase());
    }

    for (const m of src.matchAll(IPV4_RE)) addHost(m[0]);

    for (const [type, re] of HASH_RES) {
      for (const m of src.matchAll(re)) {
        const h = m[0];
        // Require both digits and letters so long decimal numbers or words aren't hashes.
        if (/\d/.test(h) && /[a-f]/i.test(h)) add(type, h.toLowerCase(), '');
      }
    }

    for (const m of src.matchAll(CVE_RE)) add('CVE', m[0].toUpperCase(), '');

    items.sort(function (a, b) { return TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type); });
    return items;
  }

  /**
   * Return the whole text with every URL, domain, IP and email defanged,
   * so it can be pasted into a ticket or chat without becoming clickable.
   */
  function defangText(text) {
    if (typeof text !== 'string' || text === '') return '';
    const items = extract(text).filter(function (i) { return i.defanged !== i.value; });
    if (items.length === 0) return text;
    const map = new Map();
    items.forEach(function (i) { map.set(i.value.toLowerCase(), i); });
    const values = items.map(function (i) { return i.value; }).sort(function (a, b) { return b.length - a.length; });
    const escaped = values.map(function (v) { return v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); });
    const re = new RegExp(escaped.join('|'), 'gi');
    return text.replace(re, function (match) {
      const item = map.get(match.toLowerCase());
      return item ? defangValue(item.type, match) : match;
    });
  }

  function toCsv(items) {
    const esc = function (s) { return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const rows = ['type,value_defanged,note'];
    items.forEach(function (i) { rows.push([i.type, i.defanged, i.note].map(esc).join(',')); });
    return rows.join('\n');
  }

  const api = { extract: extract, defangText: defangText, defangValue: defangValue, refang: refang, toCsv: toCsv };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.DecodoraIOC = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

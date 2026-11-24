/*
 * Decodora IOC extractor & ticket formatter.
 *
 * Pulls indicators of compromise (URLs, domains, IPv4s, IPv6s, emails, hashes, CVEs)
 * out of decoded or raw alert text, produces safe defanged copies, and formats
 * ready-to-paste Markdown triage summaries for SOC tickets (Jira, ServiceNow, TheHive).
 *
 * Pure logic: no DOM access, no network access. Works in the browser
 * (window.DecodoraIOC) and in Node.js (module.exports) for testing.
 */
(function (root) {
  'use strict';

  // Comprehensive ICANN gTLD, ccTLD, and high-abuse phishing/C2 TLD allowlist.
  // File and script extensions that collide with TLDs (.ps1, .exe, .sh, .py, .md, .zip, .mov ...)
  // are deliberately excluded so script/file names inside payloads are never reported as domains.
  const TLDS = new Set((
    'com net org edu gov mil int info biz name pro mobi asia ' +
    'io co ai app dev cloud online site website space tech store shop live link click ' +
    'xyz top icu buzz club fun work today life world email network digital solutions services ' +
    'support help center host page win bid loan download stream review ' +
    'cfd sbs cyou vip bond lat lol monster rest quest cam bar hair autos skin boats mom ' +
    'gdn kim wang xin men party trade date faith racing science webcam accountant ' +
    'ltd group company zone fyi wtf guru expert media agency studio design ' +
    'finance capital fund market cash money credit tax law care health clinic ' +
    'game games play bet casino poker chat social community forum blog news press wiki guide tips ' +
    'video audio music art film radio show events travel flights hotel ' +
    'house homes estate property land build energy green eco bio food cafe coffee ' +
    'deals sale discount cheap free plus express delivery direct global ' +
    'city town place areadirectory gallery photos pics ' +
    'ru su cn hk tw jp kr in id vn th my sg ph pk bd ir iq tr sa ae il ' +
    'uk de fr nl be ch at it es pt se no fi dk ie eu pl cz sk hu ro bg gr ua by kz lt lv ee ' +
    'us ca mx br ar cl pe ve co au nz za ng ke eg ma ' +
    'me tv cc ws la to gg im ly gd tk ml ga cf gq pw nu fm am ' +
    'onion test example invalid localhost local corp lan internal'
  ).split(/\s+/));

  // Common file/script extensions that must never be treated as bare domains or URL hosts.
  const FILE_EXTENSIONS = new Set((
    'ps1 psm1 psd1 exe dll bat cmd vbs vbe js mjs cjs jsx ts tsx py pyc sh bash zsh ' +
    'rb pl php jar class war ear msi cab bin dat log txt csv tsv json jsonl xml yml yaml ' +
    'ini cfg conf properties toml tmp bak old swp zip rar 7z tar gz tgz bz2 xz ' +
    'pdf doc docx xls xlsx ppt pptx rtf odt ods odp png jpg jpeg gif svg ico webp bmp ' +
    'mp3 mp4 avi mov mkv wav flac ogg html htm css scss less vue svelte ' +
    'go rs c cc cpp cxx h hpp cs java kt swift sql db sqlite sqlite3 mdb ' +
    'pcap pcapng evtx evt etl sys drv ocx cpl scr lnk iso img vhd vhdx vmdk ova ovf'
  ).split(/\s+/));

  // Redirect/wrapper infrastructure: reported, but tagged so analysts don't block
  // Microsoft, Proofpoint, Mimecast, or Barracuda by accident.
  const WRAPPER_HOSTS = /(?:^|\.)(?:safelinks\.protection\.outlook\.com|urldefense(?:\.proofpoint)?\.com|mimecast(?:protect)?\.com|linkprotect\.cudasvc\.com)$/i;

  const TYPE_ORDER = ['URL', 'Domain', 'IPv4', 'IPv6', 'Email', 'SHA256', 'SHA1', 'MD5', 'CVE'];

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

  function defangIpv6(ip) {
    return ip.replace(/:/g, '[:]');
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
    // Neutralise URLs and emails nested in the query string (redirect wrappers), so no part stays clickable.
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
    if (type === 'IPv6') return defangIpv6(value);
    return value;
  }

  /* ------------------------------------------------------------------ */
  /* Classification helpers                                             */
  /* ------------------------------------------------------------------ */

  function extractTld(host) {
    const idx = host.lastIndexOf('.');
    return idx === -1 ? '' : host.slice(idx + 1).toLowerCase();
  }

  function validTld(host, fromExplicitUrl) {
    const tld = extractTld(host);
    if (!tld || FILE_EXTENSIONS.has(tld)) return false;
    if (TLDS.has(tld)) return true;
    // When extracted from an explicit http(s):// URL authority, accept valid 2-24 alpha ICANN TLDs
    // as long as they are not known file extensions.
    return Boolean(fromExplicitUrl && /^[a-z]{2,24}$/.test(tld));
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

  function ipv6Note(ip) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'loopback';
    if (/^fe[89ab][0-9a-f]:/.test(lower)) return 'link-local';
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return 'unique-local';
    if (/^ff[0-9a-f]{2}:/.test(lower)) return 'multicast';
    if (/^2001:0?db8:/.test(lower)) return 'documentation';
    return '';
  }

  function isIpv4(s) {
    return /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s);
  }

  // Validate standard 8-group or :: compressed IPv6 (excluding timestamps and PowerShell :: method calls).
  function isValidIpv6(candidate) {
    if (!candidate || !candidate.includes(':')) return false;
    const dbl = candidate.split('::');
    if (dbl.length > 2) return false;
    const segRe = /^[0-9a-fA-F]{1,4}$/;
    if (dbl.length === 1) {
      const parts = candidate.split(':');
      return parts.length === 8 && parts.every(function (p) { return segRe.test(p); });
    }
    const left = dbl[0] ? dbl[0].split(':') : [];
    const right = dbl[1] ? dbl[1].split(':') : [];
    if (left.length + right.length >= 8) return false;
    if (left.length + right.length < 2 && candidate !== '::1') return false;
    return left.every(function (p) { return segRe.test(p); }) && right.every(function (p) { return segRe.test(p); });
  }

  // Bare dotted tokens that are really .NET / PowerShell / JS type or object names.
  function looksLikeCodeIdentifier(token) {
    return /^(?:System|Microsoft|Net|IO|Text|Convert|Runtime|Reflection|Security|Diagnostics|Threading|Collections|Management|Windows|Win32|PowerShell|window|document|console|navigator|location|Object|Array|String|Number|Boolean|Math|JSON|Promise|RegExp|Error|Buffer|process|module|exports)\./.test(token);
  }

  function trimUrl(url) {
    let u = url;
    // If a pipe '|' appeared in a URL that has no query string (e.g. "curl http://1.2.3.4/a.sh|sh"),
    // split at the pipe; keep '|' inside query strings (e.g. Outlook SafeLinks "&data=05|02|").
    const qIdx = u.indexOf('?');
    const pIdx = u.indexOf('|');
    if (pIdx !== -1 && (qIdx === -1 || pIdx < qIdx)) {
      u = u.slice(0, pIdx);
    }
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
    // Bracketed IPv6 host in URL: http://[2001:db8::1]:8080/path
    const v6 = host.match(/^\[([0-9a-fA-F:]+)\](?::\d+)?$/);
    if (v6) return v6[1].toLowerCase();
    host = host.replace(/:\d+$/, '');
    return host.toLowerCase();
  }

  /* ------------------------------------------------------------------ */
  /* Extraction                                                         */
  /* ------------------------------------------------------------------ */

  const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>`^{}\\]+/gi;
  const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])/g;
  const DOMAIN_RE = /(?<![A-Za-z0-9_@.$-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])/g;
  const IPV4_RE = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d|\.\d)/g;
  const IPV6_RE = /(?<![A-Za-z0-9_.\]:-])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){1,5}[0-9a-fA-F]{1,4}|::1)(?![A-Za-z0-9_.\[:-])/g;
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
      const normalized = (type === 'Domain' || type === 'Email' || type === 'IPv6') ? value.toLowerCase() : value;
      const key = type + '|' + normalized;
      if (seen.has(key)) return;
      seen.add(key);
      items.push({ type: type, value: value, defanged: defangValue(type, value), note: note || '' });
    }

    function addHost(host, fromExplicitUrl) {
      if (!host) return;
      if (isIpv4(host)) add('IPv4', host, ipNote(host));
      else if (isValidIpv6(host)) add('IPv6', host.toLowerCase(), ipv6Note(host));
      else if (host.includes('.') && validTld(host, fromExplicitUrl)) {
        add('Domain', host, WRAPPER_HOSTS.test(host) ? 'wrapper' : '');
      }
    }

    for (const m of src.matchAll(URL_RE)) {
      const url = trimUrl(m[0]);
      const host = urlHost(url);
      if (!host) continue;
      add('URL', url, WRAPPER_HOSTS.test(host) ? 'wrapper' : '');
      addHost(host, true);
      // "https://login.microsoftonline.com@203.0.113.47/" -> the part before "@" is a lure, not the host.
      const auth = (url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i) || [])[1] || '';
      const at = auth.lastIndexOf('@');
      if (at > 0) {
        const lure = auth.slice(0, at).replace(/:.*$/, '').toLowerCase();
        if (lure.includes('.') && validTld(lure, true) && !isIpv4(lure)) add('Domain', lure, 'lure (@ userinfo)');
      }
    }

    for (const m of src.matchAll(EMAIL_RE)) {
      const email = m[0];
      if (validTld(email, false)) add('Email', email, '');
    }

    for (const m of src.matchAll(DOMAIN_RE)) {
      const token = m[0];
      if (isIpv4(token) || looksLikeCodeIdentifier(token)) continue;
      addHost(token.toLowerCase(), false);
    }

    for (const m of src.matchAll(IPV4_RE)) addHost(m[0], false);

    for (const m of src.matchAll(IPV6_RE)) {
      if (isValidIpv6(m[0])) add('IPv6', m[0].toLowerCase(), ipv6Note(m[0]));
    }

    for (const [type, re] of HASH_RES) {
      for (const m of src.matchAll(re)) {
        const h = m[0];
        // Require both digits and letters so long decimal numbers or words aren't hashes.
        if (/\d/.test(h) && /[a-f]/i.test(h)) add(type, h.toLowerCase(), '');
      }
    }

    for (const m of src.matchAll(CVE_RE)) add('CVE', m[0].toUpperCase(), '');

    const compareByType = function (a, b) {
      return TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type);
    };
    return typeof items.toSorted === 'function' ? items.toSorted(compareByType) : items.sort(compareByType);
  }

  /**
   * Return the whole text with every URL, domain, IPv4, IPv6 and email defanged,
   * so it can be pasted into a ticket or chat without becoming clickable.
   */
  function defangText(text) {
    if (typeof text !== 'string' || text === '') return '';
    const items = extract(text).filter(function (i) { return i.defanged !== i.value; });
    if (items.length === 0) return text;
    const map = new Map();
    items.forEach(function (i) { map.set(i.value.toLowerCase(), i); });
    const byLengthDesc = function (a, b) { return b.length - a.length; };
    const rawValues = items.map(function (i) { return i.value; });
    const values = typeof rawValues.toSorted === 'function' ? rawValues.toSorted(byLengthDesc) : rawValues.sort(byLengthDesc);
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

  /**
   * Format a ready-to-paste Markdown SOC ticket summary with defanged output and IOC table.
   * @param {{steps?:string[], warnings?:string[], notes?:string[], output?:string, iocs?:{type:string,value:string,defanged:string,note:string}[]}} info
   * @returns {string}
   */
  function toTicketMarkdown(info) {
    const data = info || {};
    const text = typeof data.output === 'string' ? data.output : '';
    const steps = Array.isArray(data.steps) && data.steps.length > 0
      ? data.steps.join(' \u2192 ')
      : 'Raw input (IOC extraction & defanging)';
    const warnings = Array.isArray(data.warnings) ? data.warnings : [];
    const notes = Array.isArray(data.notes) ? data.notes : [];
    const iocs = Array.isArray(data.iocs) ? data.iocs : extract(text);
    const safeOutput = defangText(text);

    const lines = [
      '### SOC Triage Summary (Decodora)',
      '**Decode Chain:** `' + steps + '`'
    ];

    if (warnings.length > 0 || notes.length > 0) {
      lines.push('', '**Triage Notes & Warnings:**');
      warnings.forEach(function (w) { lines.push('- **Warning:** ' + w); });
      notes.forEach(function (n) { lines.push('- ' + n); });
    }

    if (safeOutput) {
      lines.push('', '**Decoded Payload (Defanged):**', '```text', safeOutput, '```');
    }

    if (iocs.length > 0) {
      lines.push(
        '',
        '**Extracted Indicators (' + iocs.length + ', Defanged):**',
        '| Type | Indicator (Defanged) | Context |',
        '| :--- | :--- | :--- |'
      );
      iocs.forEach(function (item) {
        const safeCell = String(item.defanged).replace(/\|/g, '\\|');
        const noteCell = item.note ? item.note.replace(/\|/g, '\\|') : '\u2014';
        lines.push('| ' + item.type + ' | `' + safeCell + '` | ' + noteCell + ' |');
      });
    } else {
      lines.push('', '**Extracted Indicators:** None detected');
    }

    return lines.join('\n');
  }

  const api = {
    extract: extract,
    defangText: defangText,
    defangValue: defangValue,
    refang: refang,
    toCsv: toCsv,
    toTicketMarkdown: toTicketMarkdown
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.DecodoraIOC = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

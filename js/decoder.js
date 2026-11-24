/*
 * Decodora decoder core.
 *
 * Pure decoding and deobfuscation logic with no DOM access and no network access.
 * Works in the browser (exposed as window.DecodoraDecoder) and in Node.js
 * (module.exports) so it can be tested from the command line.
 *
 * Supported modes:
 *  - 'auto'    : Automatically detects Base64/PS, Base85, Obfuscated URL, Hex, or Reversed strings
 *  - 'base64'  : Base64 (standard, URL-safe, JWT, PEM/Certutil, shell base64 -d, JS atob) and
 *                PowerShell (-EncodedCommand, FromBase64String, -bxor, char arrays, -f format, concat)
 *  - 'base85'  : Ascii85 (<~...~> or raw) and RFC 1924 / Python Base85
 *  - 'url'     : Percent-encoding, Quoted-Printable URLs, defanged URLs, SafeLinks, Proofpoint,
 *                Mimecast, Barracuda, generic redirects, and obfuscated IPs (Hex, Dword, Octal)
 *  - 'hex'     : Raw hex strings, 0x bytes, [byte[]] arrays, \xNN escapes, \uNNNN escapes
 *  - 'reverse' : Reverses backwards commands, scripts, URLs, inline reversed literals, and multi-layer payloads
 *
 * Design rules:
 *  - Decoded content is only ever returned as a string. It is never evaluated.
 *  - Any change made to the input (cleanup, padding, removed characters) is
 *    reported back as a note or a warning. Nothing is changed silently.
 */
(function (root) {
  'use strict';

  // Every accepted abbreviation of PowerShell's -EncodedCommand parameter.
  const PS_ENC_FLAG = /^(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$/i;
  // PowerShell accepts '-', '/', and Unicode dashes as parameter prefixes.
  const FLAG_PREFIX = /^[-/\u2013\u2014\u2015]/;
  const QUOTES = /^["'`\u201C\u201D\u2018\u2019]+|["'`\u201C\u201D\u2018\u2019]+$/g;
  const BASE64_TOKEN = /^[A-Za-z0-9+/=_-]+$/;
  const TOKEN_BOUNDARY_RE = /["'`\u201C\u201D\u2018\u2019,;})\]|&\\]/;

  const MAX_HEX_BYTES = 8192;
  const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g;

  // RFC 1924 / Python base64.b85encode alphabet (85 chars)
  const B85_RFC_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
  const B85_RFC_MAP = new Int16Array(128).fill(-1);
  for (let i = 0; i < B85_RFC_ALPHABET.length; i++) {
    B85_RFC_MAP[B85_RFC_ALPHABET.charCodeAt(i)] = i;
  }

  // Known URL shortener domains (offline advisory)
  const SHORTENER_DOMAINS = new Set([
    'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'is.gd', 'v.gd',
    'rb.gy', 'cutt.ly', 'ow.ly', 'tiny.cc', 'shorturl.at', 'rebrand.ly',
    'bl.ink', 'buff.ly', 'lnkd.in', 'youtu.be', 'goo.gl', 's.id'
  ]);

  /* ------------------------------------------------------------------ */
  /* Shared utilities                                                   */
  /* ------------------------------------------------------------------ */

  function stripZeroWidth(str, ctx) {
    const matches = str.match(ZERO_WIDTH_RE);
    if (matches && matches.length > 0) {
      if (ctx) {
        ctx.warnings.push(matches.length + ' invisible zero-width Unicode character(s) were stripped from the input (common obfuscation trick).');
      }
      return str.replace(ZERO_WIDTH_RE, '');
    }
    return str;
  }

  function stripShellObfuscation(str) {
    // Strip PowerShell/CMD line-continuation escapes (`\n or ^\n) and char-level ticks/carets on flags/cmdlets
    return str.replace(/[`^]\r?\n[ \t]*/g, '').replace(/[`^](?=[A-Za-z0-9\-_/\\.:])/g, '');
  }

  function stripQuotes(s) {
    return s.replace(QUOTES, '');
  }

  function describeChar(ch) {
    const code = ch.codePointAt(0);
    if (code < 0x21 || code === 0x7f) return 'U+' + code.toString(16).toUpperCase().padStart(4, '0');
    return '"' + ch + '"';
  }

  function concatBytes(chunks) {
    const total = chunks.reduce(function (n, c) { return n + c.length; }, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
  }

  function printableRatio(str) {
    let total = 0;
    let bad = 0;
    for (const ch of str) {
      total++;
      const c = ch.codePointAt(0);
      if (c === 0xfffd || (c < 0x20 && c !== 9 && c !== 10 && c !== 13) || (c >= 0x7f && c < 0xa0)) bad++;
    }
    return total === 0 ? 1 : 1 - bad / total;
  }

  function countReplacement(str) {
    let n = 0;
    for (const ch of str) if (ch === '\uFFFD') n++;
    return n;
  }

  function tryDecode(encoding, bytes, fatal) {
    try {
      return new TextDecoder(encoding, { fatal: fatal, ignoreBOM: false }).decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function decodeUtf16(bytes, enc, label, ctx) {
    let data = bytes;
    if (data.length % 2 === 1) {
      data = data.subarray(0, data.length - 1);
      ctx.warnings.push('The decoded data has an odd number of bytes, which is not valid ' + label +
        '. The last byte was ignored; the input may be truncated.');
    }
    const text = tryDecode(enc, data, false);
    const bad = countReplacement(text);
    if (bad > 0) {
      ctx.warnings.push(bad + ' invalid ' + label + ' sequence(s) were shown as "\uFFFD". The output may be incomplete or inaccurate.');
    }
    return { text: text, encoding: label };
  }

  function detectText(bytes, ctx) {
    const b = bytes;

    // Byte Order Marks
    if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) {
      const text = tryDecode('utf-8', b, false);
      const bad = countReplacement(text);
      if (bad > 0) ctx.warnings.push(bad + ' invalid UTF-8 sequence(s) were shown as "\uFFFD". The output may be incomplete or inaccurate.');
      return { text: text, encoding: 'UTF-8 (with BOM)' };
    }
    if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return decodeUtf16(b, 'utf-16le', 'UTF-16LE', ctx);
    if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) return decodeUtf16(b, 'utf-16be', 'UTF-16BE', ctx);

    // UTF-16 without BOM: ASCII text in UTF-16LE has a zero in every odd byte.
    if (b.length >= 2) {
      const pairs = Math.floor(b.length / 2);
      let zeroEven = 0;
      let zeroOdd = 0;
      for (let i = 0; i < pairs * 2; i += 2) {
        if (b[i] === 0) zeroEven++;
        if (b[i + 1] === 0) zeroOdd++;
      }
      if (zeroOdd / pairs >= 0.25 && zeroEven / pairs <= 0.05) return decodeUtf16(b, 'utf-16le', 'UTF-16LE', ctx);
      if (zeroEven / pairs >= 0.25 && zeroOdd / pairs <= 0.05) return decodeUtf16(b, 'utf-16be', 'UTF-16BE', ctx);
    }

    // -EncodedCommand is always UTF-16LE, even for non-Latin text.
    if (ctx.hint === 'utf-16le' && b.length % 2 === 0) {
      const t = tryDecode('utf-16le', b, true);
      if (t !== null && printableRatio(t) >= 0.95) return { text: t, encoding: 'UTF-16LE' };
    }

    // Strict UTF-8 (plain ASCII is a subset of UTF-8).
    const utf8 = tryDecode('utf-8', b, true);
    if (utf8 !== null && printableRatio(utf8) >= 0.85) {
      const ascii = b.every(function (x) { return x < 0x80; });
      if (ctx.hint === 'utf-16le') {
        ctx.notes.push('PowerShell -EncodedCommand normally uses UTF-16LE, but this content decodes as ' + (ascii ? 'ASCII' : 'UTF-8') + '.');
      }
      return { text: utf8, encoding: ascii ? 'ASCII / UTF-8' : 'UTF-8' };
    }

    return null;
  }

  async function inflate(bytes, format) {
    if (typeof DecompressionStream === 'undefined') return { bytes: new Uint8Array(0), error: new Error('unsupported') };
    const chunks = [];
    let error = null;
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
      const reader = stream.getReader();
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        chunks.push(r.value);
      }
    } catch (e) {
      error = e;
    }
    return { bytes: concatBytes(chunks), error: error };
  }

  function isZlibHeader(b) {
    return b.length >= 2 && (b[0] & 0x0f) === 8 && (b[0] >> 4) <= 7 && ((b[0] << 8) | b[1]) % 31 === 0;
  }

  function isCompressedBinary(b) {
    return (b.length >= 3 && b[0] === 0x1f && b[1] === 0x8b && b[2] === 0x08) || isZlibHeader(b);
  }

  function knownSignature(b) {
    const startsWith = function (arr) { return arr.every(function (v, i) { return b[i] === v; }); };
    if (startsWith([0x4d, 0x5a])) return 'a Windows executable or DLL (starts with "MZ")';
    if (startsWith([0x50, 0x4b, 0x03, 0x04])) return 'a ZIP archive (or Office document / JAR)';
    if (startsWith([0x25, 0x50, 0x44, 0x46])) return 'a PDF document';
    if (startsWith([0x7f, 0x45, 0x4c, 0x46])) return 'a Linux executable (ELF)';
    if (startsWith([0xd0, 0xcf, 0x11, 0xe0])) return 'a legacy Office document (OLE)';
    if (startsWith([0x89, 0x50, 0x4e, 0x47])) return 'a PNG image';
    if (startsWith([0xff, 0xd8, 0xff])) return 'a JPEG image';
    return null;
  }

  function hexDump(bytes) {
    const lines = [];
    const n = Math.min(bytes.length, MAX_HEX_BYTES);
    for (let off = 0; off < n; off += 16) {
      const row = bytes.subarray(off, Math.min(off + 16, n));
      let hex = '';
      let asc = '';
      for (let i = 0; i < 16; i++) {
        if (i < row.length) {
          hex += row[i].toString(16).padStart(2, '0') + ' ';
          asc += row[i] >= 0x20 && row[i] < 0x7f ? String.fromCharCode(row[i]) : '.';
        } else {
          hex += '   ';
        }
        if (i === 7) hex += ' ';
      }
      lines.push(off.toString(16).padStart(8, '0') + '  ' + hex + ' |' + asc + '|');
    }
    return lines.join('\n');
  }

  function revealControlChars(text, ctx) {
    let count = 0;
    const out = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, function (ch) {
      count++;
      return '\\x' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
    });
    if (count > 0) {
      ctx.notes.push(count + ' invisible control character(s) are shown as \\xNN (for example \\x00) so they are not hidden.');
    }
    return out;
  }

  async function bytesToOutput(bytes, ctx, depth) {
    const found = detectText(bytes, ctx);
    if (found) {
      ctx.steps.push(found.encoding);
      return revealControlChars(found.text, ctx);
    }

    if (depth === 0) {
      let format = null;
      let label = null;
      if (bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08) {
        format = 'gzip'; label = 'Gzip';
      } else if (isZlibHeader(bytes)) {
        format = 'deflate'; label = 'Zlib';
      }

      if (format) {
        const r = await inflate(bytes, format);
        if (r.bytes.length > 0) {
          ctx.steps.push(label + ' decompressed');
          if (r.error) {
            ctx.warnings.push('The ' + label + ' data is incomplete or corrupted. Only the part that could be decompressed is shown; the end of the output is probably missing.');
          }
          return bytesToOutput(r.bytes, ctx, depth + 1);
        }
        ctx.warnings.push('The data looks ' + label + '-compressed but could not be decompressed. It may be corrupted.');
      } else {
        const r = await inflate(bytes, 'deflate-raw');
        if (!r.error && r.bytes.length > 0) {
          const sub = { steps: [], notes: [], warnings: [], hint: null };
          const t = detectText(r.bytes, sub);
          if (t && sub.warnings.length === 0) {
            ctx.steps.push('Raw Deflate decompressed', t.encoding);
            ctx.notes.push.apply(ctx.notes, sub.notes);
            return revealControlChars(t.text, ctx);
          }
        }
      }
    }

    const lenient = tryDecode('utf-8', bytes, false);
    if (printableRatio(lenient) >= 0.75) {
      ctx.steps.push('UTF-8 (partial)');
      ctx.warnings.push('The data is not fully valid text. ' + countReplacement(lenient) +
        ' unreadable byte sequence(s) are shown as "\uFFFD". The output may be incomplete or inaccurate.');
      return revealControlChars(lenient, ctx);
    }

    ctx.steps.push('Binary data (hex view)');
    const sig = knownSignature(bytes);
    if (!sig && ctx.looksLikeWords) {
      throw new Error('This does not look like Base64 (it decodes to random bytes, and the input contains several words separated by spaces). Paste only the encoded text or a PowerShell command containing -EncodedCommand / -enc.');
    }
    ctx.warnings.push('The decoded data is binary, not text' + (sig ? ' \u2014 it looks like ' + sig : '') +
      '. It is shown as a hex dump. Handle with care; it was not executed or saved.');
    if (bytes.length > MAX_HEX_BYTES) {
      ctx.warnings.push('Only the first ' + MAX_HEX_BYTES + ' of ' + bytes.length + ' bytes are shown in the hex view.');
    }
    return hexDump(bytes);
  }

  /* ------------------------------------------------------------------ */
  /* Mode 1: Base64, PowerShell, JWT, Shell/JS Wrappers & Deobfuscation */
  /* ------------------------------------------------------------------ */

  const PEM_ARMOR_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/i;
  const SHELL_B64_PIPE_RE = /(?:(?:echo(?:\s+-[neE]+)*|printf)\s+(?:["']([A-Za-z0-9+/=_\s-]+)["']|([A-Za-z0-9+/=_-]{8,}))\s*\|\s*(?:\/[A-Za-z0-9_./-]*\/)?\bbase64\s+(?:-[dDi]|--decode)\b|\bbase64\s+(?:-[dDi]|--decode)\s*<<<\s*["']?([A-Za-z0-9+/=_-]{8,})["']?)/i;
  const JS_ATOB_RE = /\batob\s*\(\s*\(*\s*((?:["'`\u201C\u201D\u2018\u2019][^"'`\u201C\u201D\u2018\u2019]+["'`\u201C\u201D\u2018\u2019]\s*(?:\+\s*)?)+)\)*\s*\)/i;
  const NODE_BUFFER_B64_RE = /\bBuffer\.from\s*\(\s*(['"`])([A-Za-z0-9+/=_\s-]+)\1\s*,\s*(['"`])base64\3\s*\)/i;
  const JWT_RE = /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$/;
  const CHAR_ARRAY_RE = /(?:(?:\[\s*(?:char|byte)\s*\[\s*\]\s*\]\s*@?\s*\(|String\.fromCharCode\s*\()\s*(\d{1,4}(?:\s*,\s*\d{1,4}){3,})\s*\)|\b(\d{1,4}(?:\s*,\s*\d{1,4}){3,})\s*\|\s*(?:ForEach-Object|%)\s*\{\s*\[\s*char\s*\]\s*\$_\s*\})/i;
  const PS_FORMAT_RE = /\(?\s*(["'])([^"'\r\n]{1,512})\1\s*-f\s*((?:["'][^"'\r\n]*["']\s*,\s*)+["'][^"'\r\n]*["']|["'][^"'\r\n]*["'])\s*\)?/gi;

  function isLikelyEncPayloadToken(rawNextTok) {
    if (!rawNextTok) return false;
    const unescaped = rawNextTok.replace(/\\"/g, '"').replace(/\\'/g, "'");
    const strippedLead = unescaped.replace(/^["'`\u201C\u201D\u2018\u2019]+/, '');
    if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(strippedLead.replace(/[;,}"']+$/, ''))) return true;
    // Reject function calls like node -e 'eval(...)' where '(' immediately follows an identifier
    const bMatch = strippedLead.match(TOKEN_BOUNDARY_RE);
    const candidate = bMatch ? strippedLead.slice(0, bMatch.index) : strippedLead;
    if (strippedLead[candidate.length] === '(') return false;
    return candidate.length >= 4 && BASE64_TOKEN.test(candidate);
  }

  function hasPowerShellHint(raw) {
    const cleaned = stripShellObfuscation(raw).replace(/\\"/g, '"');
    const tokens = cleaned.trim().split(/\s+/);
    for (let i = 0; i < tokens.length - 1; i++) {
      const tok = stripQuotes(tokens[i]);
      if (FLAG_PREFIX.test(tok) && PS_ENC_FLAG.test(tok.slice(1)) && isLikelyEncPayloadToken(tokens[i + 1])) {
        return true;
      }
    }
    return /FromBase64String\s*\(/i.test(cleaned);
  }

  function hasScriptObfuscationHint(raw) {
    const cleaned = stripShellObfuscation(raw);
    if ((/char\s*\[\s*\]|byte\s*\[\s*\]|fromCharCode/i.test(cleaned)) && CHAR_ARRAY_RE.test(cleaned)) return true;
    if (/\s-f\s*["']/i.test(cleaned)) {
      PS_FORMAT_RE.lastIndex = 0;
      if (PS_FORMAT_RE.test(cleaned)) return true;
    }
    return false;
  }

  function hasBase64WrapperHint(raw) {
    const s = raw.trim();
    return (
      hasPowerShellHint(s) ||
      hasScriptObfuscationHint(s) ||
      (/-----BEGIN /i.test(s) && PEM_ARMOR_RE.test(s)) ||
      (/\bbase64\b/i.test(s) && SHELL_B64_PIPE_RE.test(s)) ||
      (/\batob\s*\(/i.test(s) && JS_ATOB_RE.test(s)) ||
      (/Buffer\.from\s*\(/i.test(s) && NODE_BUFFER_B64_RE.test(s)) ||
      (s.startsWith('eyJ') && JWT_RE.test(s))
    );
  }

  function joinQuotedConcat(expr) {
    const chunkRe = /^\s*(?:["'`\u201C\u201D\u2018\u2019]([^"'`\u201C\u201D\u2018\u2019]*)["'`\u201C\u201D\u2018\u2019])(?:\s*\+\s*["'`\u201C\u201D\u2018\u2019]([^"'`\u201C\u201D\u2018\u2019]*)["'`\u201C\u201D\u2018\u2019])*\s*$/;
    if (!chunkRe.test(expr)) return null;
    const parts = [];
    const litRe = /["'`\u201C\u201D\u2018\u2019]([^"'`\u201C\u201D\u2018\u2019]*)["'`\u201C\u201D\u2018\u2019]/g;
    let m;
    while ((m = litRe.exec(expr)) !== null) parts.push(m[1]);
    return parts.length > 0 ? { joined: parts.join(''), pieces: parts.length } : null;
  }

  function deobfuscateScriptExpressions(raw, ctx) {
    let text = stripShellObfuscation(raw);
    let changed = false;

    // 1. Char-code / byte-code decimal arrays: [char[]]@(104,116,...) or String.fromCharCode(...)
    text = text.replace(CHAR_ARRAY_RE, function (full, g1, g2) {
      const listStr = g1 || g2;
      const codes = listStr.split(/\s*,\s*/).map(Number);
      if (codes.some(function (n) { return Number.isNaN(n) || n < 0 || n > 0x10FFFF; })) return full;
      changed = true;
      ctx.steps.push('Character code array (' + codes.length + ' chars)');
      return codes.map(function (c) { return String.fromCodePoint(c); }).join('');
    });
    // Clean trailing PowerShell -join '' / -join "" after a replaced char array
    if (changed) {
      text = text.replace(/^\(([\s\S]+?)\)\s*-join\s*(?:''|"")\s*$/i, '$1');
    }

      // 2. PowerShell -f format operator: ("{1}{0}" -f 'EX','I')
    PS_FORMAT_RE.lastIndex = 0;
    if (/\s-f\s*["']/i.test(text) && PS_FORMAT_RE.test(text)) {
      PS_FORMAT_RE.lastIndex = 0;
      text = text.replace(PS_FORMAT_RE, function (full, q, tpl, argsRaw) {
        const args = [];
        const argRe = /["']([^"']*)["']/g;
        let m;
        while ((m = argRe.exec(argsRaw)) !== null) args.push(m[1]);
        if (args.length === 0) return full;
        changed = true;
        return tpl.replace(/\{(\d+)\}/g, function (ph, idx) {
          const n = Number(idx);
          return n < args.length ? args[n] : ph;
        });
      });
      if (changed) ctx.steps.push('PowerShell -f format string resolved');
    }

    // 3. Adjacent concatenated string literals: "htt"+"p://evil.com" or 'a'+'b'
    const concatJoined = text.replace(/(["'])([^"'\r\n]+)\1(?:\s*\+\s*\1([^"'\r\n]+)\1)+/g, function (full, quote) {
      const cat = joinQuotedConcat(full);
      if (!cat || cat.pieces < 2) return full;
      changed = true;
      return quote + cat.joined + quote;
    });
    if (concatJoined !== text) {
      text = concatJoined;
      ctx.notes.push('Concatenated string literals were joined.');
    }

    return { text: text, changed: changed };
  }

  function detectXorKey(str) {
    const m = str.match(/(?:-bxor|\^)\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\b/i);
    if (!m) return null;
    const rawKey = m[1];
    const key = /^0x/i.test(rawKey) ? parseInt(rawKey, 16) : parseInt(rawKey, 10);
    return (key > 0 && key <= 255) ? { key: key, label: rawKey } : null;
  }

  function cleanEncToken(tok) {
    // Strip leading quote(s), then truncate at the first JSON/shell/quote delimiter
    const unescaped = tok.replace(/\\"/g, '"').replace(/\\'/g, "'");
    const strippedLead = unescaped.replace(/^["'`\u201C\u201D\u2018\u2019]+/, '');
    const boundaryMatch = strippedLead.match(TOKEN_BOUNDARY_RE);
    if (boundaryMatch) {
      return {
        value: strippedLead.slice(0, boundaryMatch.index),
        hitBoundary: true
      };
    }
    return { value: strippedLead, hitBoundary: strippedLead.length !== unescaped.length };
  }

  function extractBase64Payload(raw, ctx) {
    let input = stripZeroWidth(raw, ctx).trim();
    const deobf = stripShellObfuscation(input);
    if (deobf !== input && hasPowerShellHint(input)) {
      ctx.notes.push('PowerShell/CMD escape characters (` or ^) were normalized before extracting the payload.');
      input = deobf;
    }

    const xorInfo = detectXorKey(input);
    if (xorInfo) ctx.xorInfo = xorInfo;

    // a) PowerShell command line: powershell.exe -nop -w hidden -enc <payload>
    const normalizedForTokens = input.replace(/\\"/g, '"');
    const tokens = normalizedForTokens.split(/\s+/);
    for (let i = 0; i < tokens.length - 1; i++) {
      const tok = stripQuotes(tokens[i]);
      if (FLAG_PREFIX.test(tok) && PS_ENC_FLAG.test(tok.slice(1)) && isLikelyEncPayloadToken(tokens[i + 1])) {
        const nextTok = tokens[i + 1];
        // Handle simple variable assignment like $p='...'+'...'; powershell -enc $p
        const cleanVarTok = nextTok.replace(/[;,}"']+$/, '');
        if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(cleanVarTok)) {
          const varName = cleanVarTok.slice(1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const assignMatch = input.match(new RegExp('\\$' + varName + '\\s*=\\s*([^;\\r\\n]+)'));
          if (assignMatch) {
            const cat = joinQuotedConcat(assignMatch[1]);
            if (cat) {
              ctx.steps.push('PowerShell ' + tok + ' argument (via ' + cleanVarTok + ')');
              ctx.hint = 'utf-16le';
              if (cat.pieces > 1) ctx.notes.push('Concatenated string pieces inside ' + cleanVarTok + ' were joined.');
              return cat.joined;
            }
          }
        }
        const firstClean = cleanEncToken(nextTok);
        const parts = [firstClean.value];
        if (!firstClean.hitBoundary) {
          for (let j = i + 2; j < tokens.length; j++) {
            const nextRaw = tokens[j];
            if (FLAG_PREFIX.test(nextRaw)) break;
            const nextClean = cleanEncToken(nextRaw);
            const prev = parts[parts.length - 1];
            if (prev.endsWith('=') || !nextClean.value || !BASE64_TOKEN.test(nextClean.value)) break;
            parts.push(nextClean.value);
            if (nextClean.hitBoundary) break;
          }
        }
        ctx.steps.push('PowerShell ' + tok + ' argument');
        ctx.hint = 'utf-16le';
        if (parts.length > 1) {
          ctx.warnings.push('The encoded argument appeared to be split into ' + parts.length +
            ' pieces (e.g. line-wrapped). They were joined together. If the output looks wrong at the end, check that no unrelated text was included.');
        }
        return parts.join('');
      }
    }

    // b) [Convert]::FromBase64String('<payload>' or ('chunk1' + 'chunk2'))
    const fromB64Re = /FromBase64String\s*\(\s*\(*\s*((?:["'\u201C\u201D\u2018\u2019][^"'\u201C\u201D\u2018\u2019]+["'\u201C\u201D\u2018\u2019]\s*(?:\+\s*)?)+)\)*\s*\)/gi;
    const matches = [...input.matchAll(fromB64Re)];
    if (matches.length > 0) {
      const blobs = matches.map(function (m) {
        const cat = joinQuotedConcat(m[1]);
        if (cat && cat.pieces > 1) {
          ctx.notes.push('Concatenated Base64 string segments (' + cat.pieces + ' pieces) were joined.');
        }
        return cat ? cat.joined : stripQuotes(m[1].trim());
      });
      if (blobs.length > 1) {
        ctx.multipleBlobs = blobs;
        ctx.steps.push('FromBase64String(...) arguments (' + blobs.length + ' payloads)');
        ctx.notes.push('Found and decoded all ' + blobs.length + ' FromBase64String(...) calls in the script.');
      } else {
        ctx.steps.push('FromBase64String(...) argument');
      }
      return blobs[0];
    }

    // c) PEM / Certutil armor: -----BEGIN ...----- <base64> -----END ...-----
    const pemMatch = input.match(PEM_ARMOR_RE);
    if (pemMatch) {
      ctx.steps.push('PEM / Certutil armor stripped');
      ctx.notes.push('Removed "-----BEGIN ' + pemMatch[1].toUpperCase() + '-----" header and footer before Base64 decoding.');
      return pemMatch[2].trim();
    }

    // d) POSIX shell pipe / herestring: echo "<b64>" | base64 -d
    const shellMatch = input.match(SHELL_B64_PIPE_RE);
    if (shellMatch) {
      ctx.steps.push('Shell base64 -d argument');
      return (shellMatch[1] || shellMatch[2] || shellMatch[3]).trim();
    }

    // e) JavaScript atob('...') or Buffer.from('...', 'base64')
    const atobMatch = input.match(JS_ATOB_RE);
    if (atobMatch) {
      ctx.steps.push('JavaScript atob(...) argument');
      const cat = joinQuotedConcat(atobMatch[1]);
      if (cat && cat.pieces > 1) ctx.notes.push('Concatenated string segments inside atob(...) were joined.');
      return cat ? cat.joined : stripQuotes(atobMatch[1].trim());
    }

    const bufMatch = input.match(NODE_BUFFER_B64_RE);
    if (bufMatch) {
      ctx.steps.push('Buffer.from(..., "base64") argument');
      return bufMatch[2].trim();
    }

    // f) Treat the whole input as Base64.
    const unquoted = stripQuotes(input);
    if (unquoted !== input) ctx.notes.push('Surrounding quotation marks were removed.');
    return unquoted;
  }

  function decodeUrlEncodedBase64(s, ctx) {
    if (!/%2[bBfF]|%3[dD]/i.test(s)) return s;
    const withoutPct = s.replace(/%2[bB]/g, '+').replace(/%2[fF]/g, '/').replace(/%3[dD]/g, '=');
    if (/^[A-Za-z0-9+/=_-]+$/.test(withoutPct)) {
      if (ctx) ctx.notes.push('URL-encoded Base64 characters (%2B/%2F/%3D) were percent-decoded.');
      return withoutPct;
    }
    return s;
  }

  function base64ToBytes(payload, ctx) {
    let s = stripZeroWidth(payload, ctx);

    ctx.looksLikeWords = s.split('\n').some(function (line) {
      return line.trim().split(/[ \t]+/).length >= 4;
    });

    if (/\s/.test(s)) {
      s = s.replace(/\s+/g, '');
      ctx.notes.push('Spaces and line breaks were removed from the Base64 text.');
    }

    s = decodeUrlEncodedBase64(s, ctx);

    if (/[-_]/.test(s)) {
      if (/[+/]/.test(s)) {
        ctx.warnings.push('The input mixes standard (+ /) and URL-safe (- _) Base64 characters. "-" and "_" were treated as "+" and "/". Output may be inaccurate.');
      } else {
        ctx.notes.push('URL-safe Base64 detected ("-" and "_"); converted to the standard alphabet.');
      }
      s = s.replace(/-/g, '+').replace(/_/g, '/');
    }

    const invalid = s.match(/[^A-Za-z0-9+/=]/gu) || [];
    if (invalid.length > 0) {
      const ratio = invalid.length / [...s].length;
      if (ratio > 0.1) {
        throw new Error('This does not look like Base64: ' + invalid.length +
          ' characters are not valid Base64. Paste only the encoded text or a PowerShell command containing -EncodedCommand / -enc.');
      }
      const unique = [...new Set(invalid)].slice(0, 10).map(describeChar).join(', ');
      ctx.warnings.push(invalid.length + ' invalid character(s) were removed before decoding (' + unique +
        '). The input may be corrupted; the output may be incomplete or inaccurate.');
      s = s.replace(/[^A-Za-z0-9+/=]/gu, '');
    }

    const segments = s.split(/=+/).filter(Boolean);
    if (segments.length === 0) throw new Error('No Base64 data found in the input.');
    if (segments.length > 1) {
      ctx.warnings.push('Padding ("=") was found in the middle of the data, which usually means several Base64 strings were joined. Each part was decoded separately and the results combined. Verify the output.');
    }

    const endsWithPadding = s.endsWith('=');
    const chunks = [];
    segments.forEach(function (seg, idx) {
      const isLast = idx === segments.length - 1;
      let part = seg;
      const rem = part.length % 4;
      if (rem === 1) {
        part = part.slice(0, -1);
        ctx.warnings.push('The Base64 length is invalid (one extra character' +
          (segments.length > 1 ? ' in part ' + (idx + 1) : '') +
          '). The last character was ignored. The input is probably truncated or corrupted, so the end of the output may be missing or wrong.');
      } else if (rem !== 0) {
        part += rem === 2 ? '==' : '=';
        if (isLast && !endsWithPadding) {
          ctx.notes.push('Missing Base64 padding ("=") was added automatically.');
        }
      }
      if (part.length === 0) return;
      const bin = atob(part);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      chunks.push(bytes);
    });

    return concatBytes(chunks);
  }

  function decodeJwtToken(jwtStr, ctx) {
    const parts = jwtStr.split('.');
    const subCtxH = { steps: [], notes: [], warnings: [], hint: null };
    const subCtxP = { steps: [], notes: [], warnings: [], hint: null };
    const hBytes = base64ToBytes(parts[0], subCtxH);
    const pBytes = base64ToBytes(parts[1], subCtxP);
    const hText = tryDecode('utf-8', hBytes, true);
    const pText = tryDecode('utf-8', pBytes, true);
    if (!hText || !pText) return null;
    ctx.steps.push('JWT (Header + Payload)', 'ASCII / UTF-8');
    ctx.notes.push('Decoded JSON Web Token (JWT) header and payload claims. The cryptographic signature segment was omitted.');
    let hFormatted = hText;
    let pFormatted = pText;
    try { hFormatted = JSON.stringify(JSON.parse(hText), null, 2); } catch (e) {}
    try { pFormatted = JSON.stringify(JSON.parse(pText), null, 2); } catch (e) {}
    return revealControlChars(hFormatted + '\n' + pFormatted, ctx);
  }

  function maybeApplyXor(bytes, xorInfo, ctx) {
    if (!xorInfo) return bytes;
    const xored = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      xored[i] = bytes[i] ^ xorInfo.key;
    }
    const checkCtx = { steps: [], notes: [], warnings: [], hint: ctx.hint };
    if (detectText(xored, checkCtx) || isCompressedBinary(xored)) {
      ctx.steps.push('XOR (key ' + xorInfo.label + ')');
      ctx.notes.push('Applied single-byte XOR key (' + xorInfo.label + ') detected in the script.');
      return xored;
    }
    return bytes;
  }

  async function runBase64Mode(raw, ctx) {
    const cleanTrimmed = stripQuotes(stripZeroWidth(raw, ctx).trim());

    // 1. Check for JWT (header.payload.signature)
    if (JWT_RE.test(cleanTrimmed)) {
      const jwtOut = decodeJwtToken(cleanTrimmed, ctx);
      if (jwtOut !== null) return jwtOut;
    }

    // 2. Check for PowerShell / JS script-level obfuscation (char arrays, -f format, string concat)
    if (!hasPowerShellHint(raw) && hasScriptObfuscationHint(raw)) {
      const deobf = deobfuscateScriptExpressions(raw, ctx);
      if (deobf.changed) {
        return revealControlChars(deobf.text, ctx);
      }
    }

    // 3. Standard / wrapped Base64 & PowerShell extraction
    const payload = extractBase64Payload(raw, ctx);

    if (ctx.multipleBlobs && ctx.multipleBlobs.length > 1) {
      const decodedParts = [];
      let totalBytes = 0;
      for (let i = 0; i < ctx.multipleBlobs.length; i++) {
        const subCtx = { steps: [], notes: [], warnings: [], hint: ctx.hint };
        let b = base64ToBytes(ctx.multipleBlobs[i], subCtx);
        totalBytes += b.length;
        b = maybeApplyXor(b, ctx.xorInfo, subCtx);
        const partOut = await bytesToOutput(b, subCtx, 0);
        decodedParts.push(partOut);
        ctx.warnings.push.apply(ctx.warnings, subCtx.warnings);
      }
      ctx.steps.push('Base64 (' + totalBytes + ' bytes total)');
      return decodedParts.join('\n');
    }

    let bytes = base64ToBytes(payload, ctx);
    ctx.steps.push('Base64 (' + bytes.length + ' bytes)');
    if (bytes.length === 0) {
      throw new Error('The input decoded to zero bytes. It is too short or not Base64.');
    }
    bytes = maybeApplyXor(bytes, ctx.xorInfo, ctx);
    return bytesToOutput(bytes, ctx, 0);
  }

  /* ------------------------------------------------------------------ */
  /* Mode 2: Base85 (Ascii85 & RFC 1924 / Python Base85)                */
  /* ------------------------------------------------------------------ */

  function decodeAscii85Bytes(str, ctx) {
    const out = [];
    let tuple = 0;
    let count = 0;

    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      const code = str.charCodeAt(i);

      if (ch === 'z' && count === 0) {
        out.push(0, 0, 0, 0);
        continue;
      }
      if (ch === 'y' && count === 0) {
        out.push(0x20, 0x20, 0x20, 0x20);
        continue;
      }
      if (code < 33 || code > 117) {
        throw new Error('Invalid Ascii85 character ' + describeChar(ch) + ' at position ' + (i + 1) + '.');
      }

      tuple = tuple * 85 + (code - 33);
      count++;
      if (count === 5) {
        if (tuple > 0xFFFFFFFF) {
          ctx.warnings.push('An Ascii85 5-character block exceeded the maximum 32-bit value (0xFFFFFFFF). The input may be corrupted.');
        }
        out.push((tuple >>> 24) & 0xff, (tuple >>> 16) & 0xff, (tuple >>> 8) & 0xff, tuple & 0xff);
        tuple = 0;
        count = 0;
      }
    }

    if (count === 1) {
      ctx.warnings.push('The Base85 input ended with 1 leftover character, which cannot form a byte and was ignored. The input may be truncated.');
    } else if (count > 1) {
      for (let p = count; p < 5; p++) tuple = tuple * 85 + 84;
      for (let b = 0; b < count - 1; b++) {
        out.push((tuple >>> (24 - b * 8)) & 0xff);
      }
    }

    return new Uint8Array(out);
  }

  function decodeRfc1924Bytes(str, ctx) {
    const out = [];
    let tuple = 0;
    let count = 0;

    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      const val = code < 128 ? B85_RFC_MAP[code] : -1;
      if (val === -1) {
        throw new Error('Invalid Base85 (RFC 1924) character ' + describeChar(str[i]) + ' at position ' + (i + 1) + '.');
      }
      tuple = tuple * 85 + val;
      count++;
      if (count === 5) {
        if (tuple > 0xFFFFFFFF) {
          ctx.warnings.push('A Base85 5-character block exceeded the maximum 32-bit value (0xFFFFFFFF). The input may be corrupted.');
        }
        out.push((tuple >>> 24) & 0xff, (tuple >>> 16) & 0xff, (tuple >>> 8) & 0xff, tuple & 0xff);
        tuple = 0;
        count = 0;
      }
    }

    if (count === 1) {
      ctx.warnings.push('The Base85 input ended with 1 leftover character, which cannot form a byte and was ignored. The input may be truncated.');
    } else if (count > 1) {
      for (let p = count; p < 5; p++) tuple = tuple * 85 + 84;
      for (let b = 0; b < count - 1; b++) {
        out.push((tuple >>> (24 - b * 8)) & 0xff);
      }
    }

    return new Uint8Array(out);
  }

  async function runBase85Mode(raw, ctx) {
    let s = stripQuotes(stripZeroWidth(raw, ctx).trim());
    if (s !== raw.trim()) {
      ctx.notes.push('Surrounding quotation marks were removed.');
    }

    const wrapped = s.match(/<~([\s\S]*?)~>/);
    let forceAscii85 = false;
    if (wrapped) {
      s = wrapped[1];
      forceAscii85 = true;
      ctx.notes.push('Ascii85 delimiters (<~ ... ~>) were detected and stripped.');
    } else if (s.startsWith('<~')) {
      s = s.slice(2);
      forceAscii85 = true;
      ctx.warnings.push('Opening "<~" delimiter found without a closing "~>" delimiter. The input may be truncated.');
    }

    if (/\s/.test(s)) {
      s = s.replace(/\s+/g, '');
      ctx.notes.push('Spaces and line breaks were removed from the Base85 text.');
    }

    if (s.length === 0) {
      throw new Error('No Base85 data found in the input.');
    }

    let bytes = null;
    let variant = '';

    if (forceAscii85) {
      bytes = decodeAscii85Bytes(s, ctx);
      variant = 'Ascii85';
    } else {
      const subA = { steps: [], notes: [], warnings: [], hint: null };
      const subR = { steps: [], notes: [], warnings: [], hint: null };
      let bytesA = null;
      let bytesR = null;

      try { bytesA = decodeAscii85Bytes(s, subA); } catch (e) {}
      try { bytesR = decodeRfc1924Bytes(s, subR); } catch (e) {}

      if (bytesA && bytesR) {
        const textA = detectText(bytesA, { steps: [], notes: [], warnings: [], hint: null });
        const textR = detectText(bytesR, { steps: [], notes: [], warnings: [], hint: null });

        if (textR && !textA) {
          bytes = bytesR; variant = 'Base85 (RFC 1924 / Python)';
          ctx.warnings.push.apply(ctx.warnings, subR.warnings);
        } else if (textA && !textR) {
          bytes = bytesA; variant = 'Ascii85';
          ctx.warnings.push.apply(ctx.warnings, subA.warnings);
        } else if (isCompressedBinary(bytesR) && !isCompressedBinary(bytesA)) {
          bytes = bytesR; variant = 'Base85 (RFC 1924 / Python)';
          ctx.warnings.push.apply(ctx.warnings, subR.warnings);
        } else if (isCompressedBinary(bytesA) && !isCompressedBinary(bytesR)) {
          bytes = bytesA; variant = 'Ascii85';
          ctx.warnings.push.apply(ctx.warnings, subA.warnings);
        } else {
          const strA = tryDecode('utf-8', bytesA, false) || '';
          const strR = tryDecode('utf-8', bytesR, false) || '';
          if (printableRatio(strR) > printableRatio(strA)) {
            bytes = bytesR; variant = 'Base85 (RFC 1924 / Python)';
            ctx.warnings.push.apply(ctx.warnings, subR.warnings);
          } else {
            bytes = bytesA; variant = 'Ascii85';
            ctx.warnings.push.apply(ctx.warnings, subA.warnings);
          }
        }
      } else if (bytesA) {
        bytes = bytesA; variant = 'Ascii85';
        ctx.warnings.push.apply(ctx.warnings, subA.warnings);
      } else if (bytesR) {
        bytes = bytesR; variant = 'Base85 (RFC 1924 / Python)';
        ctx.warnings.push.apply(ctx.warnings, subR.warnings);
      } else {
        throw new Error('This input contains characters that are not valid in either Ascii85 or standard RFC 1924 Base85.');
      }
    }

    if (!bytes || bytes.length === 0) {
      throw new Error('The Base85 input decoded to zero bytes.');
    }

    ctx.steps.push(variant + ' (' + bytes.length + ' bytes)');
    return bytesToOutput(bytes, ctx, 0);
  }

  /* ------------------------------------------------------------------ */
  /* Mode 3: URL & Obfuscated URL Decoder                               */
  /* ------------------------------------------------------------------ */

  function hasQuotedPrintableUrlHint(str) {
    // Trigger only when Quoted-Printable sequences appear inside a URL scheme/host/path
    // (before '?'), as a '=3D' query delimiter, or with soft line breaks '=\r?\n'.
    if (/=\r?\n/.test(str) && /(?:https?|hxxps?|ftp)/i.test(str)) return true;
    if (/\b(?:https?|hxxps?|ftp)(?:=3A|:)(?:=2F|\/){2}[^\s?]*=(?:2E|2F|3A|40)/i.test(str)) return true;
    if (/[?&][A-Za-z0-9_.-]+=3D/i.test(str)) return true;
    return false;
  }

  function decodeQuotedPrintableUrl(str, ctx) {
    if (!hasQuotedPrintableUrlHint(str)) return str;
    const decoded = str
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, function (_, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
    if (decoded !== str) {
      ctx.steps.push('Quoted-printable decoded');
      ctx.notes.push('MIME Quoted-Printable sequences (such as =3D or =2E) were decoded.');
    }
    return decoded;
  }

  function decodeHtmlEntities(str) {
    return str
      .replace(/&#x([0-9a-fA-F]{1,6});?/g, function (_, hex) {
        return String.fromCodePoint(parseInt(hex, 16));
      })
      .replace(/&#([0-9]{1,7});?/g, function (_, dec) {
        return String.fromCodePoint(parseInt(dec, 10));
      })
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'")
      .replace(/&colon;/gi, ':')
      .replace(/&sol;/gi, '/')
      .replace(/&period;/gi, '.');
  }

  function safePercentDecode(str, ctx) {
    let current = str.replace(/%u([0-9a-fA-F]{4})/g, function (_, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });

    try {
      return decodeURIComponent(current);
    } catch (e) {
      ctx.warnings.push('The URL contains malformed percent-encoding or non-UTF8 bytes. Valid sequences were decoded partially.');
      const bytes = [];
      let out = '';
      const flushBytes = function () {
        if (bytes.length > 0) {
          out += new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
          bytes.length = 0;
        }
      };
      for (let i = 0; i < current.length; i++) {
        if (current[i] === '%' && i + 2 < current.length && /^[0-9a-fA-F]{2}$/.test(current.slice(i + 1, i + 3))) {
          bytes.push(parseInt(current.slice(i + 1, i + 3), 16));
          i += 2;
        } else {
          flushBytes();
          out += current[i];
        }
      }
      flushBytes();
      return out;
    }
  }

  function intToIpv4(num) {
    return [
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff
    ].join('.');
  }

  function deobfuscateHostIp(host) {
    const h = host.trim();
    if (!h) return null;

    if (/^0x[0-9a-f]{1,8}$/i.test(h)) {
      const val = parseInt(h, 16);
      if (val >= 0 && val <= 0xFFFFFFFF) {
        return { ip: intToIpv4(val >>> 0), type: 'Hexadecimal IP (' + h + ')' };
      }
    }

    if (/^[0-9]{7,10}$/.test(h) && !h.startsWith('0')) {
      const val = Number(h);
      if (val >= 0 && val <= 0xFFFFFFFF) {
        return { ip: intToIpv4(val >>> 0), type: 'Decimal / Dword IP (' + h + ')' };
      }
    }

    if (/^0[0-7]{8,11}$/.test(h)) {
      const val = parseInt(h, 8);
      if (val >= 0 && val <= 0xFFFFFFFF) {
        return { ip: intToIpv4(val >>> 0), type: 'Octal IP (' + h + ')' };
      }
    }

    const parts = h.split('.');
    if (parts.length === 4) {
      let hasObfuscatedOctet = false;
      const octets = [];
      for (const p of parts) {
        if (/^0x[0-9a-f]{1,2}$/i.test(p)) {
          hasObfuscatedOctet = true;
          octets.push(parseInt(p, 16));
        } else if (/^0[0-7]{1,3}$/.test(p) && p !== '0') {
          hasObfuscatedOctet = true;
          const v = parseInt(p, 8);
          if (v > 255) return null;
          octets.push(v);
        } else if (/^(?:0|[1-9][0-9]{0,2})$/.test(p)) {
          const v = parseInt(p, 10);
          if (v > 255) return null;
          octets.push(v);
        } else {
          return null;
        }
      }
      if (hasObfuscatedOctet) {
        return { ip: octets.join('.'), type: 'Obfuscated dotted IP (' + h + ')' };
      }
    }

    return null;
  }

  function unwrapProofpoint(urlStr) {
    const v3 = urlStr.match(/urldefense(?:\.proofpoint)?\.com\/v3\/__(.+?)__/i);
    if (v3) {
      return v3[1].replace(/\*/g, '%');
    }
    const v2 = urlStr.match(/urldefense\.proofpoint\.com\/v2\/url\?[^#]*?\bu=([^&\s]+)/i);
    if (v2) {
      const rawU = v2[1].replace(/-/g, '%').replace(/_/g, '/');
      try { return decodeURIComponent(rawU); } catch (e) { return rawU; }
    }
    return null;
  }

  function inspectSingleUrlStructure(urlStr, ctx) {
    let s = urlStr;
    let changed = false;
    let unwrappedTarget = null;
    const decodedParams = [];

    let urlCandidate = s;
    const rawHostMatch = s.match(/^(?:[a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?(?:[^/@\s]+@)?([^/:?#\s]+)/);
    const rawHost = rawHostMatch ? rawHostMatch[1] : '';
    const bareIpCheck = deobfuscateHostIp(rawHost);
    if (bareIpCheck && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) {
      urlCandidate = 'http://' + s;
    }

    try {
      const parsed = new URL(urlCandidate);

      // a) Phishing "@" userinfo trick
      if (parsed.username || parsed.password) {
        const fakeUser = decodeURIComponent(parsed.username + (parsed.password ? ':' + parsed.password : ''));
        ctx.warnings.push('Phishing "@" trick detected: "' + fakeUser +
          '" before the "@" is a username, NOT the domain! The actual destination host is "' + parsed.hostname + '".');
        changed = true;
      }

      // b) Punycode / IDN homograph domain
      if (/(?:^|\.)xn--/i.test(parsed.hostname)) {
        ctx.warnings.push('Punycode domain detected ("' + parsed.hostname +
          '"). Attackers sometimes use internationalized lookalike characters to spoof trusted domains.');
        changed = true;
      }

      // c) De-obfuscate IP hostnames (Hex, Dword, Octal)
      const ipInfo = bareIpCheck || deobfuscateHostIp(parsed.hostname);
      if (ipInfo) {
        ctx.steps.push(ipInfo.type + ' \u2192 ' + ipInfo.ip);
        ctx.warnings.push('Obfuscated IP address detected in hostname: ' + ipInfo.type + ' resolves to IPv4 ' + ipInfo.ip + '.');
        s = s.replace(rawHost, ipInfo.ip);
        changed = true;
      }

      // d) Unwrap redirect wrappers (Outlook SafeLinks, Mimecast, Barracuda, Google, generic redirects)
      const hostLower = parsed.hostname.toLowerCase();
      const REDIRECT_KEYS = ['url', 'u', 'q', 'a', 'href', 'redirect', 'redirect_uri', 'redirect_url', 'target', 'dest', 'destination', 'next', 'continue', 'returnto', 'goto', 'link'];

      if (/(?:^|\.)(?:mimecast\.com|mimecastprotect\.com)$/i.test(hostLower) && parsed.searchParams.has('domain')) {
        const domVal = (parsed.searchParams.get('domain') || '').trim();
        if (domVal) {
          unwrappedTarget = /^(?:https?|ftp):\/\//i.test(domVal) ? domVal : 'https://' + domVal;
          ctx.steps.push('Mimecast URL Protect unwrapped');
          ctx.notes.push('Extracted destination domain from Mimecast URL Protect wrapper.');
          changed = true;
        }
      }

      for (const [key, val] of parsed.searchParams.entries()) {
        const cleanVal = val.trim();
        if (REDIRECT_KEYS.includes(key.toLowerCase()) && /^(?:https?|hxxps?|ftp):(?:\[\:\])?\/\//i.test(cleanVal)) {
          unwrappedTarget = cleanVal;
          if (hostLower.includes('safelinks.protection.outlook.com')) {
            ctx.steps.push('Outlook SafeLinks unwrapped');
            ctx.notes.push('Extracted destination URL from Microsoft Outlook SafeLinks wrapper.');
          } else if (hostLower.includes('cudasvc.com')) {
            ctx.steps.push('Barracuda LinkProtect unwrapped');
            ctx.notes.push('Extracted destination URL from Barracuda LinkProtect wrapper.');
          } else {
            ctx.steps.push('Redirect wrapper unwrapped (' + parsed.hostname + ')');
            ctx.notes.push('Extracted destination URL from "' + key + '" redirect parameter on ' + parsed.hostname + '.');
          }
          changed = true;
        } else if (cleanVal.length >= 8 && /^[A-Za-z0-9+/=_-]+$/.test(cleanVal)) {
          try {
            const subCtx = { steps: [], notes: [], warnings: [], hint: null };
            const b = base64ToBytes(cleanVal, subCtx);
            const t = detectText(b, subCtx);
            if (t && b.length >= 4 && printableRatio(t.text) >= 0.9 && t.text !== cleanVal) {
              decodedParams.push(key + ' (Base64 ' + t.encoding + '): ' + revealControlChars(t.text, ctx));
            }
          } catch (e) {}
        }
      }

      // e) Known URL shorteners
      const baseHost = hostLower.replace(/^www\./, '');
      if (SHORTENER_DOMAINS.has(baseHost)) {
        ctx.steps.push('Shortened URL (' + baseHost + ')');
        ctx.warnings.push('Shortened URL detected (' + baseHost + '). Because Decodora runs 100% offline to protect your OPSEC, it never connects to external servers to follow live redirects. Inspect this link in an isolated sandbox or URL-expander service.');
        changed = true;
      }
    } catch (e) {
      // Not a standalone full URL
    }

    return { url: s, changed: changed, unwrappedTarget: unwrappedTarget, decodedParams: decodedParams };
  }

  function inspectUrlPass(inputUrl, ctx) {
    let s = stripQuotes(inputUrl.trim());
    let changed = false;

    // 0. Quoted-Printable URL sequences (=3D, =2E, soft line-breaks)
    const afterQp = decodeQuotedPrintableUrl(s, ctx);
    if (afterQp !== s) {
      s = afterQp;
      changed = true;
    }

    // 1. Re-fang defanged URLs & indicators
    const beforeRefang = s;
    s = s
      .replace(/\bhxxps\b/gi, 'https')
      .replace(/\bhxxp\b/gi, 'http')
      .replace(/\bfxp\b/gi, 'ftp')
      .replace(/\[\s*:\s*\]\/\/|\(\s*:\s*\)\/\//g, '://')
      .replace(/\[\s*:\/\/\s*\]/g, '://')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)/gi, '.')
      .replace(/\[\s*\/\s*\]/g, '/')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*@\s*\]|\[\s*at\s*\]|\(\s*at\s*\)/gi, '@');

    if (s !== beforeRefang) {
      changed = true;
      ctx.steps.push('Re-fanged indicators');
      ctx.notes.push('Defanged indicators (such as hxxp, [.], or [:]) were restored to standard URL format.');
    }

    // 2. Decode HTML entities
    if (/&#?[a-zA-Z0-9]+;/.test(s)) {
      const decHtml = decodeHtmlEntities(s);
      if (decHtml !== s) {
        s = decHtml;
        changed = true;
        ctx.steps.push('HTML entities decoded');
      }
    }

    // 3. Proofpoint unwrapping before general percent decoding
    const pp = unwrapProofpoint(s);
    if (pp) {
      ctx.steps.push('Proofpoint URL Defense unwrapped');
      ctx.notes.push('Extracted the target URL from a Proofpoint URL Defense wrapper.');
      s = pp;
      changed = true;
    }

    // 4. Multi-layer percent & %uXXXX decoding
    let layers = 0;
    while (layers < 5 && (/%[0-9a-fA-F]{2}/.test(s) || /%u[0-9a-fA-F]{4}/.test(s))) {
      const next = safePercentDecode(s, ctx);
      if (next === s) break;
      s = next;
      layers++;
      changed = true;
    }
    if (layers > 0) {
      ctx.steps.push('URL-decoded' + (layers > 1 ? ' (' + layers + ' layers)' : ''));
      if (layers > 1) {
        ctx.notes.push('Multi-layer percent-encoding was detected and decoded (' + layers + ' passes).');
      }
    }

    // 5. Inspect URL structure (either as a single URL or embedded URLs inside alert text)
    if (!/\s/.test(s)) {
      const single = inspectSingleUrlStructure(s, ctx);
      return {
        url: single.url,
        changed: changed || single.changed,
        unwrappedTarget: single.unwrappedTarget,
        decodedParams: single.decodedParams
      };
    }

    const decodedParams = [];
    let firstUnwrapped = null;
    const updatedText = s.replace(/\b(?:https?|ftp):\/\/[^\s"'<>`^{}\\]+/gi, function (matchedUrl) {
      const info = inspectSingleUrlStructure(matchedUrl, ctx);
      if (info.changed) changed = true;
      decodedParams.push.apply(decodedParams, info.decodedParams);
      if (info.unwrappedTarget) {
        if (!firstUnwrapped) firstUnwrapped = info.unwrappedTarget;
        return info.unwrappedTarget;
      }
      return info.url;
    });

    return {
      url: updatedText,
      changed: changed,
      unwrappedTarget: null,
      decodedParams: decodedParams
    };
  }

  function runUrlMode(raw, ctx) {
    const cleanRaw = stripZeroWidth(raw, ctx);
    const first = inspectUrlPass(cleanRaw, ctx);
    let current = first.url;
    let changed = first.changed;
    const allParams = [...first.decodedParams];
    let target = first.unwrappedTarget;
    const firstWrapper = target ? first.url : null;

    let hops = 0;
    const seen = new Set([current]);
    while (target && hops < 4 && !seen.has(target)) {
      seen.add(target);
      hops++;
      const next = inspectUrlPass(target, ctx);
      if (next.changed) changed = true;
      allParams.push.apply(allParams, next.decodedParams);
      if (next.unwrappedTarget) {
        target = next.unwrappedTarget;
      } else {
        target = next.url;
        break;
      }
    }

    ctx.warnings = [...new Set(ctx.warnings)];
    ctx.notes = [...new Set(ctx.notes)];

    if (!changed && allParams.length === 0) {
      if (/\b(?:https?|ftp):\/\//i.test(current)) {
        ctx.steps.push('URL inspected (no encoding obfuscation found)');
        ctx.notes.push('This input did not contain percent-encoding, defanged brackets, or redirect wrappers.');
      } else {
        throw new Error('No URL encoding (%XX), defanged indicators (hxxp, [.], or [:]), or obfuscated URL patterns were found in the input.');
      }
    }

    let finalOutput = target ? target : current;
    if (target && firstWrapper && target !== firstWrapper) {
      finalOutput = target + '\n\n--- Original Wrapper URL ---\n' + firstWrapper;
    }
    if (allParams.length > 0) {
      ctx.steps.push('Base64 query parameter(s) decoded');
      finalOutput += '\n\n--- Decoded Query Parameters ---\n' + allParams.join('\n');
    }

    return revealControlChars(finalOutput, ctx);
  }

  /* ------------------------------------------------------------------ */
  /* Mode 4: Hex & Escape Strings                                       */
  /* ------------------------------------------------------------------ */

  function decodeMixedEscapes(str, ctx) {
    let hadUnicode = false;
    let cur = str
      .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, function (_, h) {
        hadUnicode = true;
        return String.fromCodePoint(parseInt(h, 16));
      })
      .replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) {
        hadUnicode = true;
        return String.fromCharCode(parseInt(h, 16));
      });
    if (hadUnicode) ctx.steps.push('Unicode escapes (\\uNNNN)');

    if (/\\x[0-9a-fA-F]{2}/i.test(cur)) {
      ctx.steps.push('Hex escapes (\\xNN)');
      const utf8Dec = new TextDecoder('utf-8', { fatal: false });
      cur = cur.replace(/(?:\\x[0-9a-fA-F]{2})+/gi, function (run) {
        const bytes = new Uint8Array(run.length / 4);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(run.slice(i * 4 + 2, i * 4 + 4), 16);
        }
        return utf8Dec.decode(bytes);
      });
    }
    return cur;
  }

  async function runHexMode(raw, ctx) {
    const s = stripQuotes(stripZeroWidth(raw, ctx).trim());

    const hasHexEsc = /\\x[0-9a-fA-F]{2}/i.test(s);
    const hasUniEsc = /\\u(?:\{[0-9a-fA-F]+\}|[0-9a-fA-F]{4})/.test(s);
    if (hasHexEsc || hasUniEsc) {
      if (hasHexEsc && !hasUniEsc) {
        const hexPairs = [];
        const stripped = s.replace(/\\x([0-9a-fA-F]{2})/gi, function (_, h) {
          hexPairs.push(parseInt(h, 16));
          return '';
        }).trim();
        if (stripped.length === 0) {
          ctx.steps.push('Hex escapes (\\xNN)');
          const bytes = new Uint8Array(hexPairs);
          return bytesToOutput(bytes, ctx, 0);
        }
      }
      return revealControlChars(decodeMixedEscapes(s, ctx), ctx);
    }

    const oxMatches = s.match(/\b0x[0-9a-fA-F]{1,2}\b/gi);
    if (oxMatches && oxMatches.length >= 2) {
      const rem = s
        .replace(/\b0x[0-9a-fA-F]{1,2}\b/gi, '')
        .replace(/^(?:\[byte\[\]\]|\(byte\[\]\)|new\s+byte\[\s*\]|byte\[\s*\])/i, '')
        .replace(/[\s,;()[\]{}]+/g, '');
      if (rem.length === 0) {
        if (/[\[({]/.test(s)) {
          ctx.notes.push('Byte-array wrapper syntax (such as [byte[]], braces, or commas) was removed before decoding.');
        }
        const bytes = new Uint8Array(oxMatches.map(function (tok) { return parseInt(tok.slice(2), 16); }));
        ctx.steps.push('Hexadecimal byte array (' + bytes.length + ' bytes)');
        return bytesToOutput(bytes, ctx, 0);
      }
    }

    let cleaned = s
      .replace(/0x/gi, '')
      .replace(/[\s,:\-;]+/g, '');

    if (cleaned.length === 0) {
      throw new Error('No hexadecimal data found in the input.');
    }

    const invalid = cleaned.match(/[^0-9a-fA-F]/g) || [];
    if (invalid.length > 0) {
      const unique = [...new Set(invalid)].slice(0, 8).map(describeChar).join(', ');
      throw new Error('This does not look like valid hexadecimal data (found non-hex characters: ' + unique + ').');
    }

    if (cleaned.length % 2 === 1) {
      cleaned = cleaned.slice(0, -1);
      ctx.warnings.push('The hex input had an odd number of digits. The last digit was ignored; the input may be truncated.');
    }

    if (cleaned.length === 0) {
      throw new Error('The hex input is too short to form a byte.');
    }

    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
    }

    ctx.steps.push('Hexadecimal (' + bytes.length + ' bytes)');
    return bytesToOutput(bytes, ctx, 0);
  }

  /* ------------------------------------------------------------------ */
  /* Mode 5: Reverse Command / String Decoder                           */
  /* ------------------------------------------------------------------ */

  const FORWARD_CMD_PATTERNS = [
    /\b(?:powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|schtasks|wmic|whoami|ipconfig|systeminfo|netstat|tasklist)(?:\.exe)?\b/i,
    /(?:^|[\s;|(&"'])cmd(?:\.exe)?\s+\/[ck]\b/i,
    /\b(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Invoke-Command|Invoke-Mimikatz|New-Object|Start-Process|Get-Process|Get-ChildItem|Get-Content|Set-Content|Set-Item|Set-ExecutionPolicy|Add-MpPreference|Add-Type|FromBase64String|DownloadString|DownloadFile|DownloadData|WebClient|MemoryStream|GzipStream|DeflateStream|StreamReader)\b/i,
    /(?:^|[\s;|(&"'])(?:IEX|iex)(?=[\s("'])/,
    /(?:^|\s)-(?:NoP|NoProfile|NonI|NonInteractive|WindowStyle|ExecutionPolicy|Exec|EncodedCommand|enc|Command)\b/i,
    /\b(?:Get|Set|New|Start|Stop|Invoke|Add|Remove|Write|Read|Out|Test|Select|Where|ForEach)-[A-Z][A-Za-z0-9]+\b/,
    /\b(?:https?|hxxps?|ftp):(?:\[\s*:\s*\])?\/\/[A-Za-z0-9.\-_[\]]+/i,
    /\b(?:eval\s*\(|Function\s*\(|document\.(?:write|createElement|cookie|location)|window\.location|String\.fromCharCode|ActiveXObject|WScript\.Shell|CreateObject\s*\(|app\.launchURL)\b/i,
    /(?:^|\n)\s*#!\/(?:usr\/bin\/env\s+|bin\/)(?:ba)?sh\b/,
    /(?:^|[\s;|(&])(?:curl|wget|chmod|bash|python3?|perl|php|ruby)\s+-\S+/
  ];

  const REVERSED_STRUCTURAL_PATTERNS = [
    /\/\/(?:\]\s*:\s*\[|:)(?:sptth|ptth|spxxh|pxxh|ptf)\b/i,
    /\b(?:exe|1sp|tab|dmc|sbv|sj|lld)\.[A-Za-z0-9_-]{2,}\b/i,
    /\b[A-Za-z0-9]+-(?:teG|teS|weN|tratS|potS|ekovnI|ddA|evomeR|etirW|daeR|tuO)\b/i,
    /(?:^|\s)(?:PoN|oN|InoN|neddiH\s+W|ssapyB\s+cexE|cne|dnammoCdedocnE)-(?=\s|$)/i
  ];

  const INLINE_REVERSE_SYNTAX_RE = /(?:\[\s*-1\s*\.\.\s*-|\[\s*array\s*\]\s*::\s*Reverse\b|\.reverse\s*\(\s*\)\s*\.join)/i;

  function reverseString(str) {
    const normalized = str.replace(/\r\n/g, '\n');
    if (!/[^\x00-\x7F]/.test(normalized)) {
      return normalized.split('').reverse().join('');
    }
    if (typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function') {
      const seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
      const parts = [];
      for (const item of seg.segment(normalized)) {
        parts.push(item.segment);
      }
      return parts.reverse().join('');
    }
    return Array.from(normalized).reverse().join('');
  }

  function countMatches(str, patterns) {
    let count = 0;
    for (let i = 0; i < patterns.length; i++) {
      if (patterns[i].test(str)) count++;
    }
    return count;
  }

  function tryStrictAsciiOrUtf8(bytes) {
    if (!bytes || bytes.length < 4) return false;
    const t = detectText(bytes, { steps: [], notes: [], warnings: [], hint: null });
    return Boolean(t && printableRatio(t.text) >= 0.95);
  }

  function looksLikeReversedPayload(raw) {
    if (typeof raw !== 'string') return false;
    const s = stripZeroWidth(raw, null).trim();
    if (s.length < 5) return false;

    if (hasPowerShellHint(s)) return false;
    if (/^(?:https?|hxxps?|ftp|fxp)(?:\[\s*:\s*\])?:\/\//i.test(s) || /urldefense|safelinks/i.test(s)) return false;

    if (INLINE_REVERSE_SYNTAX_RE.test(s) && countMatches(s, REVERSED_STRUCTURAL_PATTERNS) > 0) {
      return true;
    }

    const rev = reverseString(s);
    if (rev === s) return false;

    const fwdHits = countMatches(s, FORWARD_CMD_PATTERNS);
    const revHits = countMatches(rev, FORWARD_CMD_PATTERNS);
    const revStructHits = countMatches(s, REVERSED_STRUCTURAL_PATTERNS);

    if (fwdHits === 0 && (revHits > 0 || revStructHits > 0)) {
      return true;
    }

    if (/^>~[\s\S]*~<$/.test(s)) return true;

    if (/(?:[0-9a-fA-F]{2}x\\){3,}/i.test(s) || /(?:[0-9a-fA-F]{4}u\\){3,}/i.test(s)) return true;

    const noSpace = s.replace(/\s+/g, '');
    if (/^={1,2}[A-Za-z0-9+/_-]{8,}$/.test(noSpace)) {
      try {
        const revB64 = reverseString(noSpace);
        const sub = { steps: [], notes: [], warnings: [], hint: null };
        const bytes = base64ToBytes(revB64, sub);
        if (sub.warnings.length === 0 && (tryStrictAsciiOrUtf8(bytes) || isCompressedBinary(bytes) || detectText(bytes, sub))) {
          return true;
        }
      } catch (e) {}
    }

    if (/^[A-Za-z0-9+/_-]{16,}$/.test(noSpace) && noSpace.length % 4 === 0) {
      let fwdValid = false;
      try {
        const subF = { steps: [], notes: [], warnings: [], hint: null };
        const fBytes = base64ToBytes(noSpace, subF);
        if (detectText(fBytes, subF) || isCompressedBinary(fBytes) || knownSignature(fBytes)) {
          fwdValid = true;
        }
      } catch (e) {}
      if (!fwdValid) {
        try {
          const revB64 = reverseString(noSpace);
          const subR = { steps: [], notes: [], warnings: [], hint: null };
          const rBytes = base64ToBytes(revB64, subR);
          const rText = detectText(rBytes, subR);
          if (subR.warnings.length === 0 && rText && printableRatio(rText.text) >= 0.98) {
            return true;
          }
        } catch (e) {}
      }
    }

    return false;
  }

  function runReverseMode(raw, ctx) {
    const cleaned = stripZeroWidth(raw, ctx);
    const trimmed = cleaned.trim();
    if (trimmed.length === 0) {
      throw new Error('No text found to reverse.');
    }
    if (trimmed !== cleaned) {
      ctx.notes.push('Leading or trailing whitespace was trimmed before reversing.');
    }

    // Check for inline PowerShell/JS string-reversal syntax around a reversed string literal:
    // e.g. $a='1sp.a/moc.live//:ptth'; -join $a[-1..-$a.Length]
    if (INLINE_REVERSE_SYNTAX_RE.test(trimmed)) {
      let unwrappedAny = false;
      const replaced = trimmed.replace(/(["'])([^"'\r\n]{5,})\1/g, function (full, quote, inner) {
        const flipped = reverseString(inner);
        if (countMatches(inner, REVERSED_STRUCTURAL_PATTERNS) > 0 || countMatches(flipped, FORWARD_CMD_PATTERNS) > 0) {
          unwrappedAny = true;
          return quote + flipped + quote;
        }
        return full;
      });
      if (unwrappedAny) {
        ctx.steps.push('Reversed string literal unwrapped');
        ctx.notes.push('Reversed string literal inside script reversal syntax (such as [-1..-$s.Length]) was restored to forward order.');
        return revealControlChars(replaced, ctx);
      }
    }

    const reversed = reverseString(trimmed);
    const charCount = Array.from(reversed).length;
    ctx.steps.push('Reversed string (' + charCount + ' chars)');

    if (countMatches(reversed, FORWARD_CMD_PATTERNS) > 0 && countMatches(trimmed, FORWARD_CMD_PATTERNS) === 0) {
      ctx.notes.push('Reversed command or script syntax was detected and restored to normal forward order.');
    }

    return revealControlChars(reversed, ctx);
  }

  /* ------------------------------------------------------------------ */
  /* Auto-Detection Router                                              */
  /* ------------------------------------------------------------------ */

  function detectAutoMode(raw) {
    const cleanRaw = stripZeroWidth(raw, null);
    const s = stripQuotes(cleanRaw.trim());

    // 1. PowerShell -enc / FromBase64String, PEM, shell base64 -d, JS atob, JWT, or PS char-array / -f obfuscation
    if (hasBase64WrapperHint(cleanRaw)) return 'base64';

    // 2. Ascii85 <~ ... ~> (or truncated <~...) wrapper is always Base85
    if (/^<~/.test(s)) return 'base85';

    // 3. Reversed command, URL, or reversed encoded payload
    if (looksLikeReversedPayload(cleanRaw)) return 'reverse';

    // 4. URL-encoded Base64 token check before routing raw %XX tokens to URL
    if (/%2[bBfF]|%3[dD]/i.test(s) && !/[:/]/.test(s) && !/\[\s*\.\s*\]|\(\s*\.\s*\)/.test(s) && !/\s/.test(s)) {
      const b64Cand = decodeUrlEncodedBase64(s, null);
      if (b64Cand !== s && BASE64_TOKEN.test(b64Cand)) {
        return 'base64';
      }
    }

    // 5. URL / Defanged URL / Quoted-Printable URL / SafeLinks / Proofpoint / Mimecast / Barracuda / Embedded URL in alert text
    if (
      /\b(?:https?|hxxps?|ftp|fxp):\/\//i.test(s) ||
      /\b(?:https?|hxxps?)\[\s*:\s*\]\/\//i.test(s) ||
      hasQuotedPrintableUrlHint(s) ||
      /\[\s*\.\s*\]|\(\s*\.\s*\)|\[\s*dot\s*\]/i.test(s) ||
      /urldefense(?:\.proofpoint)?\.com|safelinks\.protection\.outlook\.com|mimecast(?:protect)?\.com|linkprotect\.cudasvc\.com/i.test(s) ||
      (/(?:%[0-9a-fA-F]{2}){2,}/.test(s) && !/\s/.test(s))
    ) {
      return 'url';
    }

    // 6. Explicit \xNN / \uNNNN escapes or 0x.. hex arrays/lists
    const oxTokens = s.match(/\b0x[0-9a-fA-F]{1,2}\b/gi);
    if ((oxTokens && oxTokens.length >= 2 && s.replace(/\b0x[0-9a-fA-F]{1,2}\b/gi, '').replace(/^(?:\[byte\[\]\]|\(byte\[\]\)|new\s+byte\[\s*\]|byte\[\s*\])/i, '').replace(/[\s,;()[\]{}]+/g, '').length === 0) ||
        /\\x[0-9a-fA-F]{2}/i.test(s) ||
        /\\u(?:\{[0-9a-fA-F]{1,6}\}|[0-9a-fA-F]{4})/.test(s) ||
        /^(?:[0-9a-fA-F]{2}[:\-]){3,}[0-9a-fA-F]{2}$/.test(s)) {
      return 'hex';
    }

    // 7. Space-separated hex pairs (e.g. "48 65 6c 6c 6f")
    if (/^(?:[0-9a-fA-F]{2}\s+){2,}[0-9a-fA-F]{2}$/.test(s)) {
      return 'hex';
    }

    // 8. Continuous hex string (optional single 0x prefix, even length >= 8) where hex yields text or Gzip/Zlib
    const noSpace = s.replace(/\s+/g, '');
    const hasSingle0x = /^0x[0-9a-fA-F]{8,}$/i.test(noSpace);
    const hexBody = hasSingle0x ? noSpace.slice(2) : noSpace;
    if (hexBody.length >= 8 && hexBody.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hexBody)) {
      const hexBytes = new Uint8Array(hexBody.length / 2);
      for (let i = 0; i < hexBytes.length; i++) {
        hexBytes[i] = parseInt(hexBody.slice(i * 2, i * 2 + 2), 16);
      }
      if (hasSingle0x) return 'hex';
      if (isCompressedBinary(hexBytes)) return 'hex';
      const hexText = detectText(hexBytes, { steps: [], notes: [], warnings: [], hint: null });
      if (hexText) {
        let b64Clean = false;
        try {
          const b64Bytes = base64ToBytes(noSpace, { steps: [], notes: [], warnings: [], hint: null });
          if (tryStrictAsciiOrUtf8(b64Bytes)) b64Clean = true;
        } catch (e) {}
        if (!b64Clean) return 'hex';
      }
    }

    // 9. Base85 without <~ ~>: single token or line-wrapped block that cleanly decodes to text or compressed stream
    const isLineWrapped = !s.split(/\r?\n/).some(function (line) {
      return line.trim().split(/[ \t]+/).length >= 3;
    });
    if (noSpace.length >= 4 && isLineWrapped) {
      const allAscii85 = [...noSpace].every(function (ch) {
        const c = ch.charCodeAt(0);
        return (c >= 33 && c <= 117) || ch === 'z' || ch === 'y';
      });
      const allRfc85 = [...noSpace].every(function (ch) {
        const c = ch.charCodeAt(0);
        return c < 128 && B85_RFC_MAP[c] !== -1;
      });
      if (allAscii85 || allRfc85) {
        const nonB64 = noSpace.match(/[^A-Za-z0-9+/=_-]/g) || [];
        if (nonB64.length > 0) {
          let b85Good = false;
          try {
            const subA = { steps: [], notes: [], warnings: [], hint: null };
            const bA = allAscii85 ? decodeAscii85Bytes(noSpace, subA) : null;
            if (bA && subA.warnings.length === 0 && (tryStrictAsciiOrUtf8(bA) || isCompressedBinary(bA))) b85Good = true;
          } catch (e) {}
          try {
            const subR = { steps: [], notes: [], warnings: [], hint: null };
            const bR = !b85Good && allRfc85 ? decodeRfc1924Bytes(noSpace, subR) : null;
            if (bR && subR.warnings.length === 0 && (tryStrictAsciiOrUtf8(bR) || isCompressedBinary(bR))) b85Good = true;
          } catch (e) {}
          if (b85Good) return 'base85';
        } else if (noSpace.length >= 5) {
          let b64ReadableOrCompressed = false;
          try {
            const b64B = base64ToBytes(noSpace, { steps: [], notes: [], warnings: [], hint: null });
            if (tryStrictAsciiOrUtf8(b64B) || isCompressedBinary(b64B) || knownSignature(b64B)) b64ReadableOrCompressed = true;
          } catch (e) {}
          if (!b64ReadableOrCompressed) {
            const isCleanAscii = function (bytes) {
              return bytes && bytes.length >= 4 && bytes.every(function (x) {
                return (x >= 0x20 && x <= 0x7e) || x === 9 || x === 10 || x === 13;
              });
            };
            try {
              const sA = { steps: [], notes: [], warnings: [], hint: null };
              const bA = allAscii85 ? decodeAscii85Bytes(noSpace, sA) : null;
              if (sA.warnings.length === 0 && isCleanAscii(bA)) return 'base85';
            } catch (e) {}
            try {
              const sR = { steps: [], notes: [], warnings: [], hint: null };
              const bR = allRfc85 ? decodeRfc1924Bytes(noSpace, sR) : null;
              if (sR.warnings.length === 0 && isCleanAscii(bR)) return 'base85';
            } catch (e) {}
          }
        }
      }
    }

    // 10. Default to Base64
    return 'base64';
  }

  /* ------------------------------------------------------------------ */
  /* Public API                                                         */
  /* ------------------------------------------------------------------ */

  async function runModePass(rawInput, mode, ctx) {
    if (mode === 'base85') return await runBase85Mode(rawInput, ctx);
    if (mode === 'url') return runUrlMode(rawInput, ctx);
    if (mode === 'hex') return await runHexMode(rawInput, ctx);
    if (mode === 'reverse') return runReverseMode(rawInput, ctx);
    return await runBase64Mode(rawInput, ctx);
  }

  function detectFollowUpLayer(text, prevMode) {
    if (typeof text !== 'string') return null;
    const trimmed = text.trim();
    if (!trimmed) return null;

    if (hasBase64WrapperHint(trimmed)) return 'base64';
    if (/^<~/.test(trimmed)) return 'base85';
    if (prevMode !== 'reverse' && looksLikeReversedPayload(trimmed)) return 'reverse';

    if (prevMode !== 'url' && !/\s/.test(trimmed)) {
      if (
        /^(?:hxxps?|fxp):\/\//i.test(trimmed) ||
        /^(?:https?|hxxps?)\[\s*:\s*\]\/\//i.test(trimmed) ||
        (/\[\s*\.\s*\]|\(\s*\.\s*\)|urldefense|safelinks|mimecast|cudasvc/i.test(trimmed) && /^(?:https?|hxxps?)/i.test(trimmed)) ||
        /^https?:\/\/(?:0x[0-9a-f]+|0[0-7]{8,}|[0-9]{7,10}|[^/@\s]+@|[^\s]*%[0-9a-f]{2})/i.test(trimmed)
      ) {
        return 'url';
      }
    }

    if (!/\s/.test(trimmed)) {
      const m = detectAutoMode(trimmed);
      if (m === 'hex' || m === 'base85' || (m === 'reverse' && prevMode !== 'reverse')) return m;
      if (m === 'base64' && trimmed.length >= 12 && /^[A-Za-z0-9+/=_-]+$/.test(trimmed)) {
        return 'base64';
      }
    } else if (/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|^\[byte\[\]\]/i.test(trimmed)) {
      return 'hex';
    }
    return null;
  }

  /**
   * Decode user input.
   * @param {string} raw - Input text to decode.
   * @param {string} [mode='auto'] - 'auto' | 'base64' | 'base85' | 'url' | 'hex' | 'reverse'
   * @returns {Promise<{ok:boolean, output:string, steps:string[], notes:string[], warnings:string[], error:string|null, mode:string}>}
   */
  async function decode(raw, mode) {
    const selectedMode = (mode || 'auto').toLowerCase();
    const ctx = { steps: [], notes: [], warnings: [], hint: null };
    const result = function (ok, output, error, usedMode) {
      return {
        ok: ok,
        output: output,
        steps: ctx.steps,
        notes: ctx.notes,
        warnings: ctx.warnings,
        error: error,
        mode: usedMode || selectedMode
      };
    };

    if (typeof raw !== 'string' || raw.trim() === '') {
      return result(false, '', 'Please paste an encoded string, PowerShell command, or obfuscated URL first.', selectedMode);
    }

    const effectiveMode = selectedMode === 'auto' ? detectAutoMode(raw) : selectedMode;

    try {
      let output = await runModePass(raw, effectiveMode, ctx);

      if (selectedMode === 'auto') {
        const seen = new Set([raw.trim(), output]);
        let curMode = effectiveMode;
        for (let depth = 1; depth < 6; depth++) {
          const nextMode = detectFollowUpLayer(output, curMode);
          if (!nextMode) break;
          const nextCtx = { steps: [], notes: [], warnings: [], hint: null };
          let nextOutput = null;
          try {
            nextOutput = await runModePass(output, nextMode, nextCtx);
          } catch (e) {
            break;
          }
          if (!nextOutput || seen.has(nextOutput) || nextCtx.steps.includes('Binary data (hex view)')) {
            break;
          }
          seen.add(nextOutput);
          output = nextOutput;
          curMode = nextMode;
          ctx.steps.push('\u21B3 Layer ' + (depth + 1));
          ctx.steps.push.apply(ctx.steps, nextCtx.steps);
          ctx.notes.push.apply(ctx.notes, nextCtx.notes);
          ctx.warnings.push.apply(ctx.warnings, nextCtx.warnings);
        }
        ctx.notes = [...new Set(ctx.notes)];
        ctx.warnings = [...new Set(ctx.warnings)];
      }

      return result(true, output, null, effectiveMode);
    } catch (e) {
      return result(false, '', e && e.message ? e.message : 'Decoding failed.', effectiveMode);
    }
  }

  const api = { decode: decode, reverseString: reverseString };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.DecodoraDecoder = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

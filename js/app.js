/*
 * Decodora user interface.
 * Output is only ever written with .value / .textContent (never innerHTML),
 * so decoded content can never run as code in the page.
 */
(function () {
  'use strict';

  const input = document.getElementById('input');
  const output = document.getElementById('output');
  const status = document.getElementById('status');
  const decodeBtn = document.getElementById('decode');
  const copyBtn = document.getElementById('copy');
  const clearBtn = document.getElementById('clear');
  const copyMsg = document.getElementById('copy-msg');
  const modeGroup = document.getElementById('mode-group');
  const modeBtns = modeGroup ? Array.from(modeGroup.querySelectorAll('.mode-btn')) : [];
  const copyDefangedBtn = document.getElementById('copy-defanged');
  const copyTicketBtn = document.getElementById('copy-ticket');
  const iocCopyTicketBtn = document.getElementById('ioc-copy-ticket');
  const iocPipeLabel = document.getElementById('ioc-pipe-label');
  const samplesPanel = document.getElementById('samples-panel');
  const samplesBox = document.getElementById('samples');
  const iocPanel = document.getElementById('ioc-panel');
  const iocList = document.getElementById('ioc-list');
  const iocCount = document.getElementById('ioc-count');
  const iocMsg = document.getElementById('ioc-msg');
  const IOC = window.DecodoraIOC;
  const SAMPLES = Array.isArray(window.DecodoraSamples) ? window.DecodoraSamples : [];

  let currentMode = 'auto';
  let currentIocs = [];
  let lastDecodeResult = null;

  const PLACEHOLDERS = {
    auto: 'Paste your payload here...',
    base64: 'Paste your Base64 or PowerShell payload here...',
    base85: 'Paste your Base85 payload here...',
    url: 'Paste your obfuscated or wrapped URL here...',
    hex: 'Paste your hex payload here...',
    reverse: 'Paste your reversed payload here...'
  };

  function addList(items) {
    const ul = document.createElement('ul');
    items.forEach(function (text) {
      const li = document.createElement('li');
      li.textContent = text;
      ul.appendChild(li);
    });
    status.appendChild(ul);
  }

  function showStatus(result) {
    status.replaceChildren();
    status.className = 'status';

    const title = document.createElement('strong');
    if (!result.ok) {
      status.classList.add('error');
      title.textContent = 'Could not decode';
    } else if (result.warnings.length > 0) {
      status.classList.add('warn');
      title.textContent = '\u26A0 Decoded with warnings \u2014 the output may be incomplete or inaccurate';
    } else {
      title.textContent = '\u2713 Decoded successfully';
    }
    if (result.ok) {
      const layers = result.steps.filter(function (s) { return /^\u21B3 Layer/.test(s); }).length + 1;
      if (layers > 1) {
        const badge = document.createElement('span');
        badge.className = 'layer-badge';
        badge.textContent = layers + ' layers peeled';
        title.appendChild(badge);
      }
    }
    status.appendChild(title);

    // On failure, show only the reason to keep the message clear.
    if (!result.ok) {
      addList([result.error]);
      status.hidden = false;
      return;
    }

    if (result.steps.length > 0) {
      const steps = document.createElement('div');
      steps.className = 'steps';
      steps.textContent = 'Detected: ' + result.steps.join(' \u2192 ');
      status.appendChild(steps);
    }

    const messages = [];
    result.warnings.forEach(function (w) { messages.push('Warning: ' + w); });
    result.notes.forEach(function (n) { messages.push(n); });
    if (messages.length > 0) addList(messages);

    status.hidden = false;
  }

  /* ------------------------------------------------------------------ */
  /* IOC panel                                                          */
  /* ------------------------------------------------------------------ */

  function hideIocs() {
    currentIocs = [];
    iocList.replaceChildren();
    iocMsg.textContent = '';
    iocPanel.hidden = true;
  }

  function renderIocs(text, sourceLabel) {
    if (!IOC || !text) { hideIocs(); return; }
    currentIocs = IOC.extract(text);
    iocList.replaceChildren();
    iocMsg.textContent = '';
    if (currentIocs.length === 0) { iocPanel.hidden = true; return; }
    if (iocPipeLabel) {
      iocPipeLabel.textContent = sourceLabel || 'Piped from decoded output';
    }

    currentIocs.forEach(function (item) {
      const li = document.createElement('li');
      li.className = 'ioc-item';

      const type = document.createElement('span');
      type.className = 'ioc-type ioc-type-' + item.type.toLowerCase();
      type.textContent = item.type;
      li.appendChild(type);

      const value = document.createElement('code');
      value.className = 'ioc-value';
      value.textContent = item.defanged;
      value.title = 'Raw: ' + item.value;
      li.appendChild(value);

      if (item.note) {
        const tag = document.createElement('span');
        tag.className = 'ioc-tag';
        tag.textContent = item.note;
        li.appendChild(tag);
      }

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ioc-copy';
      btn.textContent = 'Copy';
      btn.setAttribute('aria-label', 'Copy defanged ' + item.type);
      btn.addEventListener('click', function () { copyText(item.defanged, iocMsg, item.type + ' copied (defanged).'); });
      li.appendChild(btn);

      iocList.appendChild(li);
    });

    iocCount.textContent = String(currentIocs.length);
    iocPanel.hidden = false;
  }

  // Grow/shrink the output box to its content (between CSS min-height and 560px).
  function fitOutput() {
    output.style.height = 'auto';
    output.style.height = Math.min(Math.max(output.scrollHeight + 2, 0), 560) + 'px';
  }

  async function runDecode() {
    decodeBtn.disabled = true;
    copyMsg.textContent = '';
    try {
      const rawText = input.value;
      const result = await window.DecodoraDecoder.decode(rawText, currentMode);
      const isBinary = result.steps.indexOf('Binary data (hex view)') !== -1;

      if (result.ok) {
        lastDecodeResult = result;
        output.value = result.output;
        fitOutput();
        showStatus(result);
        if (!isBinary) renderIocs(result.output, 'Piped from decoded output'); else hideIocs();
      } else {
        // Fallback: if the input is unencoded raw alert text containing IOCs, extract & defang them directly.
        const rawIocs = (IOC && rawText.trim() !== '') ? IOC.extract(rawText) : [];
        if (rawIocs.length > 0) {
          const fallbackResult = {
            ok: true,
            output: rawText.trim(),
            steps: ['Raw input (IOC extraction & defanging)'],
            notes: ['No outer encoding layer was detected; extracted ' + rawIocs.length + ' indicator(s) directly from the raw alert text.'],
            warnings: [],
            error: null,
            mode: currentMode
          };
          lastDecodeResult = fallbackResult;
          output.value = fallbackResult.output;
          fitOutput();
          showStatus(fallbackResult);
          renderIocs(fallbackResult.output, 'Extracted from raw input');
        } else {
          lastDecodeResult = result;
          output.value = '';
          fitOutput();
          showStatus(result);
          hideIocs();
        }
      }
    } finally {
      decodeBtn.disabled = false;
    }
  }

  function setMode(mode) {
    currentMode = mode;
    modeBtns.forEach(function (btn) {
      const isSelected = btn.getAttribute('data-mode') === mode;
      btn.classList.toggle('active', isSelected);
      btn.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });
    if (PLACEHOLDERS[mode]) {
      input.placeholder = PLACEHOLDERS[mode];
    }
    if (input.value.trim() !== '') {
      runDecode();
    }
  }

  async function copyText(text, msgEl, okMsg) {
    if (!text) {
      msgEl.textContent = 'Nothing to copy.';
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      msgEl.textContent = okMsg || 'Copied.';
    } catch (e) {
      // Fallback for browsers that block the Clipboard API.
      const tmp = document.createElement('textarea');
      tmp.value = text;
      tmp.setAttribute('readonly', '');
      tmp.style.position = 'fixed';
      tmp.style.opacity = '0';
      document.body.appendChild(tmp);
      tmp.select();
      const ok = document.execCommand && document.execCommand('copy');
      document.body.removeChild(tmp);
      msgEl.textContent = ok ? (okMsg || 'Copied.') : 'Copy failed \u2014 select the text and press Ctrl+C.';
    }
  }

  function copyOutput() {
    copyText(output.value, copyMsg, 'Copied.');
  }

  function copyOutputDefanged() {
    const sourceText = output.value || input.value.trim();
    if (!sourceText) { copyMsg.textContent = 'Nothing to copy.'; return; }
    const safe = IOC ? IOC.defangText(sourceText) : sourceText;
    copyText(safe, copyMsg, safe === sourceText ? 'Copied (no indicators to defang).' : 'Copied with indicators defanged.');
  }

  function copyTicketNote(msgEl) {
    const targetMsg = msgEl || copyMsg;
    const sourceText = output.value || input.value.trim();
    if (!sourceText || !IOC || typeof IOC.toTicketMarkdown !== 'function') {
      targetMsg.textContent = 'Nothing to copy.';
      return;
    }
    const md = IOC.toTicketMarkdown({
      steps: lastDecodeResult && lastDecodeResult.steps ? lastDecodeResult.steps : [],
      warnings: lastDecodeResult && lastDecodeResult.warnings ? lastDecodeResult.warnings : [],
      notes: lastDecodeResult && lastDecodeResult.notes ? lastDecodeResult.notes : [],
      output: sourceText,
      iocs: currentIocs.length > 0 ? currentIocs : IOC.extract(sourceText)
    });
    copyText(md, targetMsg, 'Ticket summary copied (Markdown, defanged).');
  }

  function clearAll() {
    input.value = '';
    output.value = '';
    output.style.height = '';
    copyMsg.textContent = '';
    lastDecodeResult = null;
    status.replaceChildren();
    status.hidden = true;
    hideIocs();
    if (samplesBox) samplesBox.querySelectorAll('.sample-btn.active').forEach(function (b) { b.classList.remove('active'); });
    input.focus();
  }

  /* ------------------------------------------------------------------ */
  /* One-click samples                                                  */
  /* ------------------------------------------------------------------ */

  function loadSample(id) {
    const sample = SAMPLES.find(function (s) { return s.id === id; });
    if (!sample) return false;
    input.value = sample.payload;
    if (samplesBox) {
      samplesBox.querySelectorAll('.sample-btn').forEach(function (b) {
        b.classList.toggle('active', b.getAttribute('data-sample') === id);
      });
    }
    setMode('auto'); // also triggers decode because the input is not empty
    return true;
  }

  if (samplesBox) {
    SAMPLES.forEach(function (s) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'sample-btn';
      btn.setAttribute('data-sample', s.id);
      btn.title = s.chain;
      const name = document.createElement('span');
      name.className = 'sample-name';
      name.textContent = s.label;
      const chain = document.createElement('span');
      chain.className = 'sample-chain';
      chain.textContent = s.chain;
      btn.appendChild(name);
      btn.appendChild(chain);
      btn.addEventListener('click', function () { loadSample(s.id); });
      samplesBox.appendChild(btn);
    });
    if (SAMPLES.length === 0 && samplesPanel) samplesPanel.hidden = true;
  }

  decodeBtn.addEventListener('click', runDecode);
  copyBtn.addEventListener('click', copyOutput);
  if (copyDefangedBtn) copyDefangedBtn.addEventListener('click', copyOutputDefanged);
  if (copyTicketBtn) copyTicketBtn.addEventListener('click', function () { copyTicketNote(copyMsg); });
  if (iocCopyTicketBtn) iocCopyTicketBtn.addEventListener('click', function () { copyTicketNote(iocMsg); });
  clearBtn.addEventListener('click', clearAll);
  document.getElementById('ioc-copy-defanged').addEventListener('click', function () {
    copyText(currentIocs.map(function (i) { return i.defanged; }).join('\n'), iocMsg, 'All indicators copied (defanged).');
  });
  document.getElementById('ioc-copy-raw').addEventListener('click', function () {
    copyText(currentIocs.map(function (i) { return i.value; }).join('\n'), iocMsg, 'All indicators copied (raw \u2014 handle with care).');
  });
  modeBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      setMode(btn.getAttribute('data-mode') || 'auto');
    });
  });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      runDecode();
    }
  });
  // Auto-decode on paste so "Paste once" unwraps and extracts IOCs immediately.
  input.addEventListener('paste', function () {
    setTimeout(function () {
      if (input.value.trim() !== '') runDecode();
    }, 0);
  });

  /* ------------------------------------------------------------------ */
  /* Hanging Light Switch Pull Cord & Theme Management                  */
  /* ------------------------------------------------------------------ */
  function initThemeAndPullCord() {
    const fixture = document.getElementById("theme-cord-container");
    const area = document.getElementById("cord-interactive-area");
    const stem = document.getElementById("rope-stem");
    const handle = document.getElementById("cord-handle");
    const bulb = document.getElementById("bulb-indicator");
    const tooltip = document.getElementById("cord-tooltip");
    const cue = document.getElementById("pull-cue");

    // Default to dark theme or saved preference
    let currentTheme = 'dark';
    try {
      const saved = localStorage.getItem("decodora-theme");
      if (saved) currentTheme = saved;
    } catch (e) {}

    function applyTheme(theme) {
      document.documentElement.setAttribute("data-theme", theme);
      try {
        localStorage.setItem("decodora-theme", theme);
      } catch (e) {}

      const isDark = theme === "dark";
      if (bulb) {
        bulb.className = isDark ? "cord-indicator-bulb bulb-off" : "cord-indicator-bulb bulb-lit";
      }
      if (tooltip) {
        tooltip.textContent = isDark ? "Pull for Lights ON (Light Mode)" : "Pull for Lights OFF (Dark Mode)";
      }
    }

    applyTheme(currentTheme);

    if (!fixture || !area || !stem || !handle) return;

    const BASE_HEIGHT = 32;
    const MAX_PULL = 36;
    const PULL_THRESHOLD = 18;

    let isDragging = false;
    let startY = 0;
    let currentStretch = 0;
    let dragStartTime = 0;

    function playTactileClick() {
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        const ctx = new AudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = "sine";
        osc.frequency.setValueAtTime(160, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(50, ctx.currentTime + 0.05);

        gain.gain.setValueAtTime(0.18, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.05);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start();
        osc.stop(ctx.currentTime + 0.05);
      } catch (e) {
        // audio disabled or blocked
      }
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const newTheme = current === "light" ? "dark" : "light";
      applyTheme(newTheme);
    }

    function snapBack(shouldToggle, finalStretch) {
      fixture.classList.remove("cord-snapping");
      const releaseHeight = BASE_HEIGHT + finalStretch;
      stem.style.setProperty("--release-height", releaseHeight + "px");
      handle.style.setProperty("--release-y", finalStretch + "px");

      stem.style.height = "";
      handle.style.transform = "";

      void fixture.offsetWidth; // force reflow
      fixture.classList.add("cord-snapping");

      if (shouldToggle) {
        toggleTheme();
        playTactileClick();
      }

      if (cue) {
        cue.style.background = "transparent";
        cue.style.boxShadow = "none";
      }

      setTimeout(function () {
        fixture.classList.remove("cord-snapping");
        stem.style.height = BASE_HEIGHT + "px";
        handle.style.transform = "translateY(0px)";
      }, 550);
    }

    area.addEventListener("pointerdown", function (e) {
      isDragging = true;
      startY = e.clientY;
      currentStretch = 0;
      dragStartTime = Date.now();
      fixture.classList.remove("cord-snapping");
      try { area.setPointerCapture(e.pointerId); } catch (err) {}
    });

    area.addEventListener("pointermove", function (e) {
      if (!isDragging) return;
      const rawDeltaY = e.clientY - startY;
      if (rawDeltaY > 0) {
        currentStretch = Math.min(MAX_PULL, Math.pow(rawDeltaY, 0.85) * 1.3);
      } else {
        currentStretch = 0;
      }
      stem.style.height = (BASE_HEIGHT + currentStretch) + "px";
      handle.style.transform = "translateY(" + currentStretch + "px)";

      if (cue) {
        if (currentStretch >= PULL_THRESHOLD) {
          cue.style.background = "#c48b54";
          cue.style.boxShadow = "0 0 8px #c48b54";
        } else {
          cue.style.background = "transparent";
          cue.style.boxShadow = "none";
        }
      }
    });

    function finishPull(e) {
      if (!isDragging) return;
      isDragging = false;
      try { area.releasePointerCapture(e.pointerId); } catch (err) {}

      const duration = Date.now() - dragStartTime;
      const finalStretch = currentStretch;
      const isQuickTap = duration < 240 && finalStretch < 8;

      if (finalStretch >= PULL_THRESHOLD || isQuickTap) {
        snapBack(true, isQuickTap ? 24 : finalStretch);
      } else {
        snapBack(false, finalStretch);
      }
    }

    area.addEventListener("pointerup", finishPull);
    area.addEventListener("pointercancel", function (e) {
      if (!isDragging) return;
      isDragging = false;
      try { area.releasePointerCapture(e.pointerId); } catch (err) {}
      snapBack(false, currentStretch);
    });

    fixture.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        snapBack(true, 24);
      }
    });
  }

  initThemeAndPullCord();

  // Editing the input by hand deselects the highlighted sample.
  input.addEventListener('input', function () {
    if (samplesBox) samplesBox.querySelectorAll('.sample-btn.active').forEach(function (b) { b.classList.remove('active'); });
  });

  // Shareable demo links: #sample=<id> loads one of the built-in samples (never user data).
  const hashMatch = window.location.hash.match(/^#sample=([a-z0-9-]+)$/i);
  if (hashMatch) loadSample(hashMatch[1]);

  // Offline support: cache the app files after the first visit.
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('sw.js').catch(function () { /* offline caching unavailable */ });
    });
  }
})();

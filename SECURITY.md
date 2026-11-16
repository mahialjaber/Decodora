# Security Policy

## Security Model & OPSEC Guarantees

**Decodora** is intentionally designed for incident responders, SOC analysts, and malware researchers who handle active malicious payloads, obfuscated stagers, and sensitive corporate telemetry.

To guarantee zero operational risk, Decodora adheres to strict security constraints:

1. **Strict Content Security Policy (CSP)**:
   ```http
   default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; worker-src 'self'; object-src 'none'; base-uri 'none'
   ```
   * `connect-src 'none'`: Decodora cannot make network requests (`fetch`, `XMLHttpRequest`, `WebSocket`, or `EventSource`). Zero bytes ever leave the browser.
2. **Offline-First PWA**:
   * Powered by a local Service Worker (`sw.js`). Decodora operates completely disconnected from the Internet and works safely inside air-gapped jump boxes or isolated malware-analysis VMs.
3. **Execution Prevention**:
   * Decoded output is strictly set using `.value` / `.textContent` on `<textarea>` and DOM elements (never `innerHTML` or `eval`), ensuring that decoded malicious scripts (PowerShell, HTML, JavaScript) are rendered as plain text and cannot execute.

## Reporting a Security Concern

If you discover a potential bypass to the client-side sandbox, a CSP loophole, or a decoding vulnerability:

* Please open a private security advisory on GitHub or email **mahialjaber.dev@gmail.com**.
* Detail the payload and reproduction steps.

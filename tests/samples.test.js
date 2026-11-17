// Run with:  node --test tests/samples.test.js
// Guarantees every one-click sample in the UI really decodes and yields IOCs.
const test = require('node:test');
const assert = require('node:assert/strict');
const { decode } = require('../js/decoder.js');
const IOC = require('../js/ioc.js');
const SAMPLES = require('../js/samples.js');

const EXPECT = {
  gzip: { output: 'https://cdn-update.malware-delivery.test/stage2.ps1', minLayers: 2 },
  safelinks: { output: 'https://login.microsoftonline.com@203.0.113.47/common/oauth2', minLayers: 1 },
  reversed: { output: 'https://invoice-portal.secure-docs.test/loader.ps1', minLayers: 3 },
  hexchain: { output: 'https://drop.evil-cdn.test/payloads/stager.bin', minLayers: 3 },
  backtick: { output: 'http://198.51.100.23/update.exe', minLayers: 1 }
};

test('sample list is well-formed', () => {
  assert.ok(SAMPLES.length >= 4);
  for (const s of SAMPLES) {
    assert.ok(s.id && s.label && s.chain && s.payload, s.id);
    assert.ok(EXPECT[s.id], 'missing expectation for ' + s.id);
  }
});

for (const s of SAMPLES) {
  test(`sample "${s.label}" decodes and yields defanged IOCs`, async () => {
    const r = await decode(s.payload);
    assert.equal(r.ok, true);
    assert.ok(r.output.includes(EXPECT[s.id].output), r.output);
    const layers = r.steps.filter((x) => /^\u21B3 Layer/.test(x)).length + 1;
    assert.ok(layers >= EXPECT[s.id].minLayers, `${s.id}: ${layers} layers`);
    const iocs = IOC.extract(r.output);
    assert.ok(iocs.length > 0);
    assert.ok(iocs.every((i) => !/^https?:\/\//i.test(i.defanged)));
    // Samples must stay harmless: reserved TLDs / documentation IPs / Microsoft example domains only.
    for (const i of iocs) {
      if (i.type === 'Domain') assert.ok(/\.(test|com)$/.test(i.value), i.value);
      if (i.type === 'IPv4') assert.ok(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(i.value), i.value);
    }
  });
}

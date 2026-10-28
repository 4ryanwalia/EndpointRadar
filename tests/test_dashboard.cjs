// Run with node tests/test_dashboard.cjs; exercises the real dashboard script without a server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../src/endpointradar/templates/dashboard.html'), 'utf8');
const script = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/)[1];
const elements = new Map();
let exportedBlob;
const element = id => {
  if (!elements.has(id)) elements.set(id, {value: id === 'findingSeverity' ? 'ALL' : '', addEventListener() {}, classList: {add() {}, remove() {}}});
  return elements.get(id);
};
const sandbox = {
  document: {getElementById: element, createElement: () => ({click() {}})},
  window: {location: {protocol: 'http:', origin: 'http://localhost'}, addEventListener() {}},
  URL: {createObjectURL(blob) { exportedBlob = blob; return 'blob:test'; }, revokeObjectURL() {}},
  Blob,
  setTimeout() {},
};
vm.createContext(sandbox);
vm.runInContext(script + `
  state.findings = [
    {severity: 'HIGH', title: '<img src=x onerror=alert(1)>', description: 'network', fix: '=CMD()'},
    {severity: 'LOW', title: 'Other', description: '', fix: 'review'}
  ];
  renderFindings();
`, sandbox);
assert.match(element('findingList').innerHTML, /&lt;img/);
assert.doesNotMatch(element('findingList').innerHTML, /<img/);
element('findingSeverity').value = 'HIGH';
element('findingSearch').value = 'network';
vm.runInContext('renderFindings(); exportFindings();', sandbox);
assert.equal(element('findingCount').textContent, '1 of 2 findings shown');
assert.doesNotMatch(element('findingList').innerHTML, /Other/);
exportedBlob.text().then(csv => {
  assert.match(csv, /"'=CMD\(\)"/);
  assert.doesNotMatch(csv, /Other/);
  console.log('Dashboard filtering, HTML escaping, and CSV safety passed.');
});

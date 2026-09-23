// Dependency-free behavioral checks for the browser controller.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
let drafts = [];
const context = vm.createContext({
  console, setTimeout, clearTimeout,
  document: {
    querySelector: selector => elements.get(selector) || null,
    querySelectorAll: selector => selector === '[data-review-note]' ? drafts : [],
    addEventListener() {},
  },
  window: {},
  fetch: async () => { throw new Error('Unexpected network request'); },
});
vm.runInContext(fs.readFileSync('app.js', 'utf8').replace(/hydrate\(\);\s*$/, ''), context);
async function run() {
  vm.runInContext("state.caseId='new'; state.sampleId='old'; state.samples=[{id:'old',case_id:'other'}]", context);
  assert.equal(vm.runInContext('selectedSample()', context), null);
  await vm.runInContext('start()', context);
  await vm.runInContext("registerSamples([{name:'test.exe'}])", context);
  elements.set('#metricEvidence', {});
  elements.set('#graphSample', {});
  elements.set('.node.find', {});
  elements.set('#evidenceList', {});
  drafts = [{dataset: {reviewNote: 'e1'}, value: 'draft <keep>'}];
  vm.runInContext("state.evidence=[{id:'e1',case_id:'new',status:'needs_review',confidence:null},{id:'e2',case_id:'new',status:'accepted'}];renderEvidence()", context);
  assert.equal(elements.get('#metricEvidence').innerHTML, '50<small>%</small>');
  assert.ok(elements.get('#evidenceList').innerHTML.includes('draft &lt;keep&gt;'));
  assert.ok(elements.get('#evidenceList').innerHTML.includes('未评分'));
  const bar = {style: {}, parentElement: {setAttribute() {}}};
  elements.set('.progress i', bar);
  vm.runInContext('renderEvidence()', context);
  assert.equal(bar.style.width, '50%');
  vm.runInContext("state.evidence = Array.from({length:25}, (_,i)=>({id:'e'+i,case_id:'new',status:'needs_review'}));state.page=1;renderEvidence()", context);
  assert.ok(elements.get('#evidenceList').innerHTML.includes('e24'));
  assert.ok(!elements.get('#evidenceList').innerHTML.includes('data-record="e0"'));
  vm.runInContext("state.samples=[{id:'s1',case_id:'new'},{id:'s2',case_id:'other'}];state.evidence=[{id:'e1',case_id:'new',sample_id:'s1'},{id:'e2',case_id:'other',sample_id:'s2'}]", context);
  vm.runInContext('state.page=0', context);
  assert.equal(vm.runInContext('graphModel().nodes.length', context), 2);
  assert.equal(vm.runInContext('graphModel().edges.length', context), 1);
  vm.runInContext('state.evidence=[];renderEvidence()', context);
  assert.ok(elements.get('#evidenceList').innerHTML.includes('暂无证据'));
  assert.equal(bar.style.width, '0%');
  const card = vm.runInContext("jobCard({id:'job1',case_id:'new',executor:'apk_static/v1',status:'running',model:'gpt-5.6-sol',result:{verification:{candidate:'<script>bad</script>'}},artifacts:['evidence/e0001.json']})", context);
  assert.ok(card.includes('data-cancel-job="job1"'));
  assert.ok(card.includes('&lt;script&gt;bad&lt;/script&gt;'));
  assert.ok(card.includes('case_id=new&amp;name=evidence%2Fe0001.json'));
  vm.runInContext("state.api=true;state.samples=[{id:'apk1',case_id:'new',stored_apk:true}];state.sampleId='apk1';refreshData=async()=>{};view=()=>{};api=async(path,options)=>{globalThis.lastJob={path,payload:JSON.parse(options.body)};return {reason:'queued'}}", context);
  elements.set('#apkModel', {value:'gpt-5.6-sol'});
  elements.set('#apkCalls', {value:'2'});
  await vm.runInContext('start()', context);
  assert.equal(vm.runInContext('lastJob.path',context), '/api/apk/jobs');
  assert.equal(vm.runInContext('lastJob.payload.model',context), 'gpt-5.6-sol');
  assert.equal(vm.runInContext('lastJob.payload.max_calls',context), 2);
  console.log('Frontend checks passed: case isolation, offline actions, review metrics and drafts.');
}
run().catch(error => { console.error(error); process.exitCode = 1; });

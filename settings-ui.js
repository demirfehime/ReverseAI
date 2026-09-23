/* Integration forms live separately from the workbench controller. */
const statusLabels={connected:'连接测试成功',models_available:'已获取模型列表',failed:'连接失败',untested:'尚未测试'};
const selectField=(name,label,options,value)=>`<label>${label}<select name="${name}">${options.map(([id,title])=>`<option value="${escapeHTML(id)}" ${id===value?'selected':''}>${escapeHTML(title)}</option>`).join('')}</select></label>`;
const checkbox=(name,label,checked=false)=>`<label class="check-label"><input type="checkbox" name="${name}" ${checked?'checked':''}> ${label}</label>`;
const optionalField=(name,label,value='',multi=false)=>field(name,label,value,multi).replace(' required','');
const statusFor=(group,id)=>state.settings?.statuses?.[`${group}/${id}`]||{status:'untested'};
const configCopy=()=>structuredClone(state.settings.config);
let skillCatalog=[];

async function renderIntegrationSettings(){
  if(!state.settings)return;
  const config=state.settings.config;
  html('#providerList',config.providers.map(p=>{
    const s=statusFor('providers',p.id);
    return `<article class="integration-card"><header><div><h2>${escapeHTML(p.id)}</h2><p>${escapeHTML(p.protocol)} · ${p.enabled?'默认 Provider 已启用':'未启用'}</p></div><mark>${statusLabels[s.status]||'尚未测试'}</mark></header><p>${escapeHTML(p.base_url)}</p><p>模型：${escapeHTML(p.model||'尚未选择')} · 密钥：${s.credential?.configured?'已设置（不会回显）':'未设置'}</p><p class="muted">${escapeHTML(s.reason||'')}${s.checked_at?' · '+when(s.checked_at):''}</p><div class="toolbar"><button data-edit-provider="${escapeHTML(p.id)}">编辑 / 设置密钥</button><button data-models="${escapeHTML(p.id)}">获取模型</button><button data-test-provider="${escapeHTML(p.id)}">测试连接</button><button data-delete-provider="${escapeHTML(p.id)}">删除</button></div>${s.models?`<p>模型列表来自服务（${s.models.length} 个）</p><div class="model-options">${s.models.map(m=>`<button data-select-model="${escapeHTML(m)}" data-provider="${escapeHTML(p.id)}">${escapeHTML(m)}</button>`).join('')}</div>`:''}</article>`;
  }).join('')||'<article class="integration-card empty-config"><h2>尚未配置 API</h2><p>点击右上角“新增 Provider”，支持 OpenAI Chat Completions、Responses 和 Anthropic Messages。可使用自定义兼容服务。</p><button class="primary" data-add-provider>＋ 新增 Provider</button></article>');
  html('#mcpList',config.mcp.map(m=>{
    const s=statusFor('mcp',m.id);
    return `<article class="integration-card"><header><h2>${escapeHTML(m.id)}</h2><mark>${statusLabels[s.status]||'尚未测试'}</mark></header><p>来源：${escapeHTML(m.source)} · ${m.enabled?'已启用只读调用':'调用未启用'}</p><p>${escapeHTML(m.url)} · ${escapeHTML(m.transport)}</p><p>${escapeHTML(s.reason||s.scope||'保存地址后点击测试连接，不会自动执行工具。')}</p><small>${s.checked_at?when(s.checked_at):''}</small><div class="toolbar"><button data-edit-mcp="${escapeHTML(m.id)}">编辑</button><button data-test-mcp="${escapeHTML(m.id)}">连接测试 / 发现工具</button>${m.source==='bethington/ghidra-mcp'?`<button data-ghidra-backend="${escapeHTML(m.id)}" ${m.enabled?'':'disabled'}>已有 Ghidra 项目</button>`:''}<button data-delete-mcp="${escapeHTML(m.id)}">移除</button></div>${s.tools?`<details><summary>${s.tools.length} 个实际发现的工具</summary>${s.tools.map(t=>`<div class="tool-row"><b>${escapeHTML(t.name)}</b><p>${escapeHTML(t.description||'')}</p>${m.enabled&&m.allowed_tools.includes(t.name)?`<button data-call-mcp="${escapeHTML(m.id)}" data-tool="${escapeHTML(t.name)}">显式只读调用</button>`:''}</div>`).join('')}</details>`:''}</article>`;
  }).join('')||'<p>没有 MCP 配置。可新增 Streamable HTTP 服务。</p>');
  try{skillCatalog=(await api('/api/skills/catalog')).items}catch(e){put('#skillList',e.message)}
  html('#skillList',skillCatalog.map(s=>{
    const key=s.id==='reverse-engineering'?'reverse-skill':s.id,entry=config.skills.find(x=>x.id===key);
    return `<article class="integration-card"><header><h2>${escapeHTML(s.name)}</h2><mark>${s.verified?'校验通过':'校验失败'}</mark></header><p>${escapeHTML(s.description)}</p><small>reverse-skill · ${escapeHTML(s.revision.slice(0,12))} · ${escapeHTML(s.path)}</small><div class="toolbar"><button data-read-skill="${escapeHTML(s.id)}">查看内容</button><button data-toggle-skill="${escapeHTML(s.id)}" ${s.verified?'':'disabled'}>${entry?.enabled?'停用':'启用文本参考'}</button></div></article>`;
  }).join('')||'<p>没有导入的 Skill 文本。</p>');
  const a=config.agents;
  html('#agentConfig',`<article class="integration-card"><h2>${a.enabled?'子 Agent 已启用':'子 Agent 已关闭'}</h2><p>委派：${a.delegation_mode==='auto'?'主 Agent 自主发起':'手动创建'} · 每个主任务最多 ${a.max_children} 个子 Agent · 最大并发 ${a.max_concurrency}（全局线程上限 8）</p><p>主任务调用预算 ${a.call_budget} · 时间预算 ${a.time_budget_seconds} 秒</p><p>子 Agent：${escapeHTML(a.provider_id||'继承默认 Provider')} / ${escapeHTML(a.model||'继承 Provider 模型')} · 文本与已有证据分析</p><p>自动模式从 Copilot 的 API 模型入口发起；任务进展在分析页查看。APK 静态分析仍使用独立 worker。</p></article>`);
  put('#delegationStatus',a.enabled&&a.delegation_mode==='auto'?'自动委派已启用 · 主 Agent 按需拆分任务':'自动委派关闭 · 可在 Agent 设置中开启');
  $('#runAgents').disabled=!a.enabled;
  const selected=$('#copilotSkill').value;
  html('#copilotSkill','<option value="">不使用 Skill</option>'+config.skills.filter(x=>x.enabled).map(s=>`<option value="${escapeHTML(s.id)}">${escapeHTML(s.id)}</option>`).join(''));
  $('#copilotSkill').value=selected;
  const active=config.providers.find(x=>x.enabled);
  $('#copilotMode').options[1].textContent=active?`${active.id} / ${active.model||'未选模型'}`:'API 模型（请先配置）';
  renderAgentJobs();
}

async function editProvider(id){
  if(!state.settings)await loadSettings();
  const p=state.settings.config.providers.find(x=>x.id===id)||{id:'provider_'+Date.now(),protocol:'chat_completions',base_url:'https://api.openai.com/v1',credential_env:'',timeout_seconds:30,model:'',enabled:false};
  let savedId=id;
  const persist=async form=>{
    const values=Object.fromEntries(form),secret=values.secret;delete values.secret;
    const entry={...values,headers:JSON.parse(values.headers||'{}'),enabled:form.has('enabled'),timeout_seconds:Number(values.timeout_seconds)},config=configCopy();
    if(savedId&&entry.id!==savedId)throw new Error('已保存的配置名称不能直接改名，请新增配置');
    if(!savedId&&config.providers.some(x=>x.id===entry.id))throw new Error('配置名称已存在');
    config.providers=config.providers.filter(x=>x.id!==entry.id).map(x=>entry.enabled?{...x,enabled:false}:x);config.providers.push(entry);
    await saveSettings(config);
    savedId=entry.id;
    if(secret)await post('/api/credentials',{group:'providers',id:entry.id,secret});
    $('[name=secret]',$('#editor')).value='';
    await loadSettings();
    return entry.id;
  };
  openEditor(id?'编辑 API Provider':'新增 API Provider',field('id','配置名称',p.id)+selectField('protocol','请求协议',[['chat_completions','OpenAI Chat Completions / 兼容 API'],['responses','OpenAI Responses'],['anthropic_messages','Anthropic Messages']],p.protocol)+field('base_url','Base URL（支持完整端点，自动避免路径重复）',p.base_url)+optionalField('secret','API Key（留空保留原密钥）')+optionalField('credential_env','或引用服务进程环境变量',p.credential_env)+optionalField('model','模型 ID（获取列表后选择，或手动填写）',p.model)+'<div class="toolbar"><button type="button" id="editorFetchModels">保存并获取模型</button></div><p id="editorModelStatus" role="status"></p><div id="editorModels" class="model-options"></div>'+field('timeout_seconds','超时（1–120 秒）',p.timeout_seconds)+optionalField('headers','附加请求头 JSON（不填写密钥）',JSON.stringify(p.headers||{}),true)+checkbox('enabled','启用为默认 Provider（不会自动发送 Case 数据）',p.enabled),async form=>{await persist(form);toast('API 配置已保存')});
  const input=$('[name=secret]');input.type='password';input.autocomplete='new-password';
  $('#editorFetchModels').onclick=async()=>{
    const form=$('#editorForm'),button=$('#editorFetchModels');if(!form.reportValidity())return;
    button.disabled=true;$('#editorSave').disabled=true;$('#editorCancel').disabled=true;put('#editorError','');put('#editorModelStatus','正在保存配置并获取模型…');
    try{
      const ident=await persist(new FormData(form)),result=await post('/api/providers/models',{id:ident});
      html('#editorModels',result.models.map(m=>`<button type="button" data-editor-model="${escapeHTML(m)}">${escapeHTML(m)}</button>`).join(''));
      $$('#editorModels button').forEach(b=>b.onclick=()=>{form.elements.model.value=b.dataset.editorModel;put('#editorModelStatus','已选择 '+b.dataset.editorModel+'，点击保存应用')});
      put('#editorModelStatus',`已获取 ${result.models.length} 个模型，点击选择后保存`);await loadSettings();
    }catch(e){put('#editorError',e.message);put('#editorModelStatus','获取失败，可修改配置后重试或手动填写模型 ID')}
    finally{button.disabled=false;$('#editorSave').disabled=false;$('#editorCancel').disabled=false}
  };
}

async function editMcp(id){
  const m=state.settings.config.mcp.find(x=>x.id===id)||{id:'mcp_'+Date.now(),source:'custom',enabled:false,transport:'streamable_http',url:'http://127.0.0.1:8081/mcp',credential_env:'',timeout_seconds:20,allowed_tools:[]};
  openEditor('MCP 服务',field('id','名称',m.id)+field('source','来源 / 项目',m.source)+field('url','Streamable HTTP 地址',m.url)+optionalField('credential_env','凭据环境变量',m.credential_env)+optionalField('secret','Bearer 凭据（留空保留）')+field('timeout_seconds','超时秒数',m.timeout_seconds)+optionalField('allowed_tools','只读工具 allowlist（每行一个，服务端还会执行只读白名单校验）',m.allowed_tools.join('\n'),true)+checkbox('enabled','启用显式只读调用',m.enabled),async form=>{
    const v=Object.fromEntries(form),secret=v.secret;delete v.secret;
    if(id&&v.id!==id)throw new Error('已保存的名称不能直接修改');
    const config=configCopy();if(!id&&config.mcp.some(x=>x.id===v.id))throw new Error('名称重复');
    config.mcp=config.mcp.filter(x=>x.id!==v.id);config.mcp.push({...v,transport:'streamable_http',enabled:form.has('enabled'),timeout_seconds:Number(v.timeout_seconds),allowed_tools:v.allowed_tools.split('\n').map(x=>x.trim()).filter(Boolean)});
    await saveSettings(config);if(secret)await post('/api/credentials',{group:'mcp',id:v.id,secret});await loadSettings();
  });$('[name=secret]').type='password';
}

function configureAgents(){
  const a=state.settings.config.agents,providers=state.settings.config.providers;
  openEditor('Agent 委派策略',checkbox('enabled','启用子 Agent',a.enabled)+selectField('delegation_mode','任务委派方式',[['manual','手动创建任务列表'],['auto','主 Agent 自主委派']],a.delegation_mode)+selectField('provider_id','子 Agent Provider',[['','继承主 Agent Provider'],...providers.map(p=>[p.id,p.id])],a.provider_id)+optionalField('model','子 Agent 模型（留空继承，可选择或输入）',a.model)+'<datalist id="agentModelOptions"></datalist>'+field('max_children','每个主任务最多创建的子 Agent 数（1–100）',a.max_children)+field('max_concurrency','每个主任务最大并发（1–8；全局上限 8）',a.max_concurrency)+field('call_budget','总调用预算（1–100；自动模式含主 Agent 和汇总）',a.call_budget)+field('time_budget_seconds','总时间预算秒数（1–3600）',a.time_budget_seconds),async form=>{
    const v=Object.fromEntries(form),c=configCopy();c.agents={...a,enabled:form.has('enabled'),delegation_mode:v.delegation_mode,provider_id:v.provider_id,model:v.model.trim(),max_children:Number(v.max_children),max_concurrency:Number(v.max_concurrency),call_budget:Number(v.call_budget),time_budget_seconds:Number(v.time_budget_seconds),allowed_tools:[]};await saveSettings(c);
  });
  const form=$('#editorForm');form.elements.model.setAttribute('list','agentModelOptions');
  const models=()=>{const id=form.elements.provider_id.value||providers.find(p=>p.enabled)?.id;html('#agentModelOptions',(statusFor('providers',id).models||[]).map(m=>`<option value="${escapeHTML(m)}"></option>`).join(''))};
  form.elements.provider_id.onchange=models;models();
  for(const [key,max] of [['max_children',100],['max_concurrency',8],['call_budget',100],['time_budget_seconds',3600]]){const input=form.elements[key];input.type='number';input.min='1';input.max=String(max);input.step='1'}
}
function runAgents(){if(!state.caseId)return toast('请先选择 Case');const caseId=state.caseId,sampleId=selectedSample()?.id;openEditor('创建受控子任务',field('tasks','任务（每行一个，不会执行代码或样本）','总结当前证据\n检查证据缺口',true)+selectField('skill','绑定 Skill',[['','不绑定'],...state.settings.config.skills.filter(x=>x.enabled).map(x=>[x.id,x.id])],''),async form=>{await post('/api/agents/run',{case_id:caseId,sample_id:sampleId,tasks:String(form.get('tasks')).split('\n').map(x=>x.trim()).filter(Boolean),skill_ids:form.get('skill')?[form.get('skill')]:[],allowed_tools:[]});await refreshData();toast('父子任务已创建，输出将进入人工复核队列')})}
function renderAgentJobsContent(){html('#agentJobs',state.jobs.filter(x=>inCase(x)&&x.type==='agent_parent').map(j=>`<article class="integration-card"><h2>${escapeHTML(j.prompt||'手动委派任务')}</h2><p>${escapeHTML(j.status)} · ${escapeHTML(j.reason)}</p><small>${escapeHTML(j.id)} · ${escapeHTML(j.model||'本地规则')}${j.calls_used!=null?` · 已占用调用预算 ${j.calls_used}/${j.budget.call_budget}`:''}</small><div class="toolbar">${['running','queued'].includes(j.status)?`<button data-cancel-agent="${escapeHTML(j.id)}">停止主任务及子任务</button>`:''}${j.evidence_id?`<button data-agent-evidence="${escapeHTML(j.evidence_id)}">查看汇总证据</button>`:''}</div><details class="agent-tree" data-parent="${escapeHTML(j.id)}"><summary>子 Agent（${(j.children||[]).length}）</summary>${state.jobs.filter(c=>inCase(c)&&c.parent_id===j.id).map(c=>`<div><b>${escapeHTML(c.prompt)}</b><p>${escapeHTML(c.status)} · ${escapeHTML(c.reason)}</p><small>${escapeHTML(c.executor)} / ${escapeHTML(c.model||'本地规则')}</small>${c.evidence_id?`<button data-agent-evidence="${escapeHTML(c.evidence_id)}">查看证据</button>`:''}</div>`).join('')||'<p>主 Agent 尚未委派子任务。</p>'}</details></article>`).join('')||'<p>当前 Case 尚无 Agent 任务。可通过 Copilot 发起自动分析，或手动创建子任务。</p>')}

async function integrationAction(button){
  if(button.disabled)return;
  button.disabled=true;
  try{
    const d=button.dataset;
    if(d.deleteProvider&&state.settings.config.agents.provider_id===d.deleteProvider)throw new Error('此 Provider 被子 Agent 使用，请先在 Agent 设置中改为继承或选择其他 Provider');
    if(d.addProvider!==undefined||d.editProvider)await editProvider(d.editProvider);
    if(d.editMcp)await editMcp(d.editMcp);
    if(d.testProvider||d.models||d.testMcp){const endpoint=d.models?'/api/providers/models':d.testMcp?'/api/mcp/test':'/api/providers/test';try{await post(endpoint,{id:d.models||d.testProvider||d.testMcp});toast('请求成功，结果已更新')}finally{await loadSettings()}}
    if(d.selectModel){const c=configCopy();c.providers.find(x=>x.id===d.provider).model=d.selectModel;await saveSettings(c);toast('模型已保存；可测试连接')}
    if(d.deleteProvider||d.deleteMcp){const group=d.deleteProvider?'providers':'mcp',id=d.deleteProvider||d.deleteMcp;openEditor('移除配置',`<p>移除 ${escapeHTML(id)} 及其本地密钥。不会删除任务或证据。</p>`,async()=>{await post('/api/credentials',{group,id,secret:''});const c=configCopy();c[group]=c[group].filter(x=>x.id!==id);await saveSettings(c)})}
    if(d.readSkill){const item=await api('/api/skills/content/'+encodeURIComponent(d.readSkill));openEditor(item.name,`<p>来源：reverse-skill · ${escapeHTML(item.revision)} · 文本参考</p><pre>${escapeHTML(item.content)}</pre>`,null)}
    if(d.toggleSkill){const item=skillCatalog.find(x=>x.id===d.toggleSkill),id=item.id==='reverse-engineering'?'reverse-skill':item.id,c=configCopy();let entry=c.skills.find(x=>x.id===id);if(!entry){entry={id,source:'zhaoxuya520/reverse-skill',version:item.revision,description:item.description.slice(0,1900),enabled:false,tasks:[],allowed_tools:[],parameters:{}};c.skills.push(entry)}entry.enabled=!entry.enabled;entry.version=item.revision;await saveSettings(c)}
    if(d.ghidraBackend){openEditor('连接已有 Ghidra 项目','<p>查找或连接本机已有 Ghidra 实例，不会导入文件或启动样本。需提前安装 Ghidra 插件并打开授权项目。</p>'+optionalField('project','项目名称（留空仅列出实例）'),async form=>{const project=String(form.get('project')).trim();const result=await post(project?'/api/mcp/connect-backend':'/api/mcp/instances',{id:d.ghidraBackend,project});toast('后端查询完成，请查看返回结果');setTimeout(()=>openEditor('Ghidra 后端返回',`<pre>${escapeHTML(JSON.stringify(result.result,null,2))}</pre>`,null),0);await loadSettings()})}
    if(d.callMcp){const status=statusFor('mcp',d.callMcp),tool=status.tools.find(x=>x.name===d.tool);openEditor('显式读取 MCP 工具',`<p>${escapeHTML(d.tool)} · 返回结果会登记为待复核证据</p><details><summary>参数 schema</summary><pre>${escapeHTML(JSON.stringify(tool.inputSchema,null,2))}</pre></details>`+field('arguments','参数 JSON','{}',true),async form=>{const sample=selectedSample();if(!sample)throw new Error('请先选择样本');await post('/api/mcp/call',{id:d.callMcp,tool:d.tool,arguments:JSON.parse(form.get('arguments')),case_id:state.caseId,sample_id:sample.id});await refreshData();toast('读取结果已登记为待复核证据')})}
    if(d.cancelAgent){await post('/api/agents/cancel',{id:d.cancelAgent,case_id:state.caseId});await refreshData()}
    if(d.agentEvidence){view('evidence');showRecord(d.agentEvidence)}
  }catch(e){toast(e.message)}finally{button.disabled=false}
}

for(const section of $$('.view:not(#overview)')){const back=document.createElement('button');back.className='back-button';back.textContent='← 返回';back.onclick=()=>view(navigation.pop()||'overview',true);section.prepend(back)}
$('#addProvider').onclick=()=>editProvider();$('#addMcp').onclick=()=>editMcp();$('#configureAgents').onclick=configureAgents;$('#runAgents').onclick=runAgents;
document.addEventListener('click',e=>{const button=e.target.closest('button');if(button&&Object.keys(button.dataset).some(k=>['addProvider','editProvider','editMcp','testProvider','models','testMcp','selectModel','deleteProvider','deleteMcp','readSkill','toggleSkill','callMcp','cancelAgent','agentEvidence','ghidraBackend'].includes(k)))integrationAction(button)});
if(state.settings)renderIntegrationSettings();

$('#copilotMode').onchange=()=>{put('.copilot>header em',$('#copilotMode').value==='provider'?'API 模型':'本地规则');put('.copilot>header small',$('#copilotMode').value==='provider'?'显式发送当前元数据与证据':'本地规则 · 非 LLM')};

function renderAgentJobs(){
  const open=new Set($$('#agentJobs details[open]').map(node=>node.dataset.parent));
  renderAgentJobsContent();
  $$('#agentJobs details').forEach(node=>{node.open=open.has(node.dataset.parent)});
}

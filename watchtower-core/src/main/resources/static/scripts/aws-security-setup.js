(function () {
 'use strict';
 // AWS Security Agent setup (approved AwsSetup board, 2026-10-22): status card + next step, Status /
 // Settings / Sample tests tabs, folded connection checks, and a sample-test result dialog that
 // shows the result first with steps and technical ids folded away.
 if(window.watchtowerAwsSetupInstalled)return;window.watchtowerAwsSetupInstalled=true;
 var MODES=[{id:'FULL',name:'Full-code review',help:'Scans the whole sample',icon:'folder_code'},{id:'DIFFERENTIAL',name:'Changed-code review',help:'Scans a sample change',icon:'difference'},{id:'CLEAN',name:'Clean-code review',help:'A sample that should have no findings',icon:'verified'}];
 var SEVERITY_TONE={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:5,INFORMATIONAL:6,INFO:6};
 var STEP_LABELS={PREFLIGHT:'AWS checks before scanning',STATIC_ANALYSIS:'Code analysis',FINALIZING:'Finishing the review'};
 var RUNNING_STATES={QUEUED:'Waiting to start',PREPARING:'Preparing sample code',INPUT_READY:'Code uploaded',CREATING:'Creating AWS review',REVIEW_READY:'AWS review created',STARTING:'Starting scan',IMPORTING:'Saving results'};
 var POLL_MS=10000;
 function node(tag,text,cls){var el=document.createElement(tag);if(text!==undefined&&text!==null)el.textContent=String(text);if(cls)el.className=cls;return el;}
 function icon(name,cls){var el=node('span',name,'material-icons'+(cls?' '+cls:''));el.setAttribute('aria-hidden','true');return el;}
 function words(value){var s=String(value||'Unknown').toLowerCase().replace(/_/g,' ');return s.charAt(0).toUpperCase()+s.slice(1);}
 function mode(id){return MODES.find(function(m){return m.id===id;})||{id:id,name:words(id),help:'',icon:'science'};}
 function full(value){return window.WatchtowerTime?window.WatchtowerTime.format(value):new Date(value).toLocaleString();}
 function short(value){return window.WatchtowerTime&&window.WatchtowerTime.short?window.WatchtowerTime.short(value):full(value);}
 function chip(text,tone,iconName,tip){var el=node('span',undefined,'wt-mini-chip'+(tone?' wt-mini-chip--'+tone:''));if(iconName)el.appendChild(icon(iconName));el.appendChild(node('span',text));if(tip){el.dataset.tip=tip;el.tabIndex=0;}return el;}
 function duration(ms){if(!(ms>0))return '—';var s=Math.round(ms/1000);if(s<60)return s+' s';var m=Math.round(s/60);return m<60?m+' min':Math.floor(m/60)+' h '+(m%60)+' min';}
 /** Completed means AWS finished, inputs were verified, nothing is missing and the code was deleted. */
 function completed(r){return !!(r&&r.state==='COMPLETE'&&r.providerStatus==='COMPLETED'&&r.inputsVerified&&r.cleanupComplete&&r.missing===0);}
 /** The clean sample has no vulnerability in it: a completed run that still reports findings did not behave as expected. */
 function unexpectedFindings(r){return completed(r)&&r.mode==='CLEAN'&&r.findings>0;}
 /** Passed means the run completed and, for the clean sample, found nothing. */
 function passed(r){return completed(r)&&!unexpectedFindings(r);}
 /** One plain outcome per test: passed, needs attention, running, stopped, or failed. */
 function outcome(r){
  if(!r)return {label:'Not run',tone:'',icon:'radio_button_unchecked',title:'not run'};
  if(unexpectedFindings(r))return {label:'Unexpected · '+r.findings+(r.findings===1?' finding':' findings'),tone:'warn',icon:'error',title:'reported findings in code that should have none',hero:'priority_high',heroTone:'is-warn'};
  if(completed(r))return {label:'Passed · '+r.findings+(r.findings===1?' finding':' findings'),tone:'ok',icon:'check_circle',title:'passed',hero:'check',heroTone:'is-ok'};
  if(!r.finished)return {label:RUNNING_STATES[r.state]||'Running',tone:'warn',icon:'hourglass_top',title:'is running',hero:'hourglass_top',heroTone:'is-warn'};
  if(r.state==='CANCELED')return {label:'Canceled',tone:'',icon:'block',title:'was canceled',hero:'block',heroTone:''};
  if(r.state==='COMPLETE')return {label:'Finished — needs attention',tone:'warn',icon:'error',title:'finished — needs attention',hero:'priority_high',heroTone:'is-warn'};
  if(r.state==='NEEDS_RECONCILIATION')return {label:'Recovery needed',tone:'warn',icon:'error',title:'needs recovery',hero:'priority_high',heroTone:'is-warn'};
  return {label:r.state==='UNAVAILABLE'?'Could not start':'Failed',tone:'bad',icon:'cancel',title:'failed',hero:'close',heroTone:'is-bad'};
 }
 /** Steps the test went through. A finished, completed test never shows a provider step as "Not started". */
 function steps(r){
  var providerDone=r.finished&&r.state==='COMPLETE'&&r.providerStatus==='COMPLETED';
  var provider=(r.progress||[]).map(function(s){var raw=String(s.status||s.state||'');var done=providerDone||/COMPLETE|SUCCEEDED/.test(raw);
   return {label:STEP_LABELS[s.name]||words(s.name),done:done,state:done?'Done':r.finished?'Did not run':words(raw||'Waiting')};});
  return [{label:'Code uploaded, checksum and encryption checked',done:!!r.inputsVerified,state:r.inputsVerified?'Done':r.sourceSha?'Preparing':'Waiting'}]
   .concat(provider,[{label:'Temporary code deleted',done:!!r.cleanupComplete,state:r.cleanupComplete?'Done':'Pending'},
    {label:'AWS review record deleted',done:!!r.reviewRetired,state:r.reviewRetired?'Done':r.reviewId?'Kept in AWS':'Not created'}]);
 }
 function init(){
  var root=document.querySelector('[data-aws-setup]');if(!root||root.dataset.initialized)return;root.dataset.initialized='true';
  var q=function(s){return root.querySelector(s);};
  var history=[],selected=null,page=0,request=null,pending=false,historyLoaded=false,nextAction=null;
  var resources=root.dataset.resourcesReady==='true',scanner=root.dataset.scannerEnabled==='true';
  var confirmDialog=q('#aws-setup-test-dialog'),resultDialog=q('#aws-setup-result-dialog');
  function status(message){q('[data-aws-status]').textContent=message;}
  async function api(path,body){var headers={Accept:'application/json'};if(body!==undefined){headers['Content-Type']='application/json';headers[root.dataset.csrfHeader]=root.dataset.csrfToken;}
   var r=await fetch('/aws-security'+path,{method:body===undefined?'GET':'POST',headers:headers,body:body===undefined?undefined:JSON.stringify(body)}),data=await r.json();
   if(!r.ok)throw new Error(data.safeMessage||data.detail||data.message||data.error||'Request failed ('+r.status+').');return data;
  }
  function latest(id){return history.find(function(r){return r.configurationCurrent&&r.mode===id;});}
  function showTab(name){
   root.querySelectorAll('[data-aws-tab]').forEach(function(tab){var on=tab.dataset.awsTab===name;tab.setAttribute('aria-selected',String(on));tab.classList.toggle('is-active',on);});
   root.querySelectorAll('[data-aws-panel]').forEach(function(panel){panel.hidden=panel.dataset.awsPanel!==name;});
  }
  function setState(el,ok,iconName){if(!el)return;el.classList.toggle('is-ok',ok);el.classList.toggle('is-warn',!ok);var i=el.querySelector('.material-icons');if(i)i.textContent=iconName;}
  function updateSummary(){
   var active=history.find(function(r){return !r.finished;}),proof=history.find(function(r){return r.configurationCurrent&&r.providerStatus==='COMPLETED'&&r.inputsVerified;});
   var ready=resources&&scanner;
   var overall=q('[data-aws-overall]');overall.classList.toggle('wt-mini-chip--ok',ready);overall.classList.toggle('wt-mini-chip--warn',!ready);
   q('[data-aws-overall-icon]').textContent=ready?'check_circle':'error_outline';q('[data-aws-overall-label]').textContent=ready?'Ready':'Setup required';
   setState(q('[data-aws-connections-state]'),resources,resources?'check_circle':'error');
   setState(q('[data-aws-scanner-state]'),scanner,scanner?'check_circle':'radio_button_unchecked');
   var role=q('[data-aws-role-state]');role.classList.toggle('wt-mini-chip--ok',!!proof);role.querySelector('.wt-dot').classList.toggle('wt-dot--ready',!!proof);
   var title,help,label;
   if(!resources){title='Fix the AWS connections';help='A connection check failed. Open the checks below to see which one.';label='Show checks';nextAction=function(){showTab('status');toggleChecks(true);};}
   else if(active){title=mode(active.mode).name+' is running';help='Wait for it to finish before starting another test.';label='View progress';nextAction=function(){return openResult(active.id);};}
   else if(!scanner){title='Turn on the AWS scanner';help='Turn on AWS Security Agent in Scanner modules before scanning repositories.';label='Open Scanner modules';nextAction=function(){location.href='/configuration/modules';};}
   else{title='AWS scans are ready';help='Repositories whose ruleset includes Security review get an AWS review on their next scan.';label='Open repositories';nextAction=function(){location.href='/repositories';};}
   q('[data-aws-next-title]').textContent=title;q('[data-aws-next-help]').textContent=help;q('[data-aws-test-label]').textContent=label;
   var hero=q('[data-aws-hero-icon]');hero.classList.toggle('is-ok',ready&&!active);hero.classList.toggle('is-warn',!ready||!!active);
   q('[data-aws-hero-symbol]').textContent=active?'hourglass_top':ready?'check':'priority_high';
   var count=MODES.filter(function(m){return passed(latest(m.id));}).length,summary=q('[data-aws-tests-summary]');
   summary.hidden=!historyLoaded;summary.textContent=count+' of 3 passed';
   renderTests(active);
  }
  function renderTests(active){
   var list=q('[data-aws-test-checklist]');list.replaceChildren();
   MODES.forEach(function(m){
    var r=latest(m.id),stale=!r&&history.some(function(old){return old.mode===m.id;}),o=outcome(r);
    var row=node('li',undefined,'wt-aws-test'),tile=node('span',undefined,'wt-aws-test__icon');tile.appendChild(icon(m.icon));row.appendChild(tile);
    var text=node('span',undefined,'wt-aws-test__text');text.appendChild(node('strong',m.name));text.appendChild(node('span',m.help,'wt-field-help'));row.appendChild(text);
    var state=node('span');state.appendChild(stale?chip('Settings changed — run again','warn','sync_problem'):chip(o.label,o.tone,o.icon));row.appendChild(state);
    var button=node(r?'md-outlined-button':'md-text-button');button.type='button';button.setAttribute('has-icon','');
    var i=icon(r?'open_in_new':'play_arrow');i.slot='icon';button.appendChild(i);button.appendChild(document.createTextNode(r?'View result':'Run'));
    button.dataset.awsTestMode=m.id;button.hidden=!r&&(!resources||!!active);
    button.addEventListener('click',function(){(r?openResult(r.id):openTest(m.id)).catch(function(e){status(e.message);});});
    row.appendChild(button);list.appendChild(row);
   });
  }
  function fact(label,value,copy){var area=q('[data-aws-result-facts]');area.appendChild(node('dt',label));var dd=node('dd');dd.appendChild(node('code',value==null?'Not recorded':value));area.appendChild(dd);
   var tool=node('dd');if(copy&&value){var b=node('button',undefined,'wt-icon-action');b.type='button';b.dataset.copyText=value;b.dataset.tip='Copy';b.setAttribute('aria-label','Copy '+label);b.appendChild(icon('content_copy'));tool.appendChild(b);}area.appendChild(tool);}
  function stat(value,label,iconName){var el=node('div',undefined,'wt-aws-stat'),b=node('strong');if(iconName)b.appendChild(icon(iconName));b.appendChild(document.createTextNode(value));el.appendChild(b);el.appendChild(node('span',label,'wt-field-help'));return el;}
  function renderReceipt(r){
   selected=r;var m=mode(r.mode),o=outcome(r);
   q('[data-aws-result-title]').textContent=m.name+' '+o.title;
   q('[data-aws-result-sub]').textContent=short(r.createdAt)+(r.requester?' · run by '+r.requester:'');
   var head=q('[data-aws-result-icon]');head.className='wt-aws-result-head__icon '+(o.heroTone||'');head.querySelector('.material-icons').textContent=o.hero||'science';
   var states=q('[data-aws-result-state]');states.replaceChildren();if(!r.configurationCurrent)states.appendChild(chip('Settings changed since this test','warn','sync_problem'));
   if(r.missing>0)states.appendChild(chip(r.missing+' results missing','warn','report'));
   if(r.reason&&!completed(r)&&r.finished)states.appendChild(chip('Why','', 'info',r.reason));
   var stats=q('[data-aws-result-stats]');stats.replaceChildren(stat(String(r.findings),r.findings===1?'finding':'findings'),
    stat(r.cleanupComplete?'Deleted':'Pending','sample code',r.cleanupComplete?'check_circle':'hourglass_top'),stat(duration(r.finishedAt-r.createdAt),'took'));
   var progress=q('[data-aws-progress]');progress.replaceChildren();
   steps(r).forEach(function(s){var li=node('li',undefined,'wt-aws-tick'+(s.done?' is-done':''));li.appendChild(icon(s.done?'check_circle':'radio_button_unchecked'));li.appendChild(node('span',s.label));if(!s.done)li.appendChild(node('span',s.state,'wt-field-help'));progress.appendChild(li);});
   q('[data-aws-result-facts]').replaceChildren();fact('Review ID',r.reviewId,true);fact('Job ID',r.jobId,true);fact('SHA-256',r.sourceSha,true);if(r.diffSha)fact('Patch SHA-256',r.diffSha,true);fact('Size',r.sourceBytes?r.sourceBytes+' bytes':null);
   q('[data-aws-test-stop]').hidden=r.finished;q('[data-aws-test-stop]').textContent=r.jobId?'Request stop':'Cancel test';
   q('[data-aws-test-recover]').hidden=r.state!=='NEEDS_RECONCILIATION'&&(!r.finished||r.cleanupComplete);
   var portal=q('[data-aws-review-link]');portal.hidden=!r.reviewUrl;portal.href=r.reviewUrl||'';
   var deletion=q('[data-aws-delete-review]'),form=q('#aws-delete-review-form');if(deletion)deletion.hidden=!r.canDeleteReview;
   if(form){form.action='/aws-security/runs/'+encodeURIComponent(r.id)+'/delete-review';form.elements.reviewId.value=r.reviewId||'';}
   q('[data-aws-pager]').hidden=!(r.pages>1);q('[data-aws-page-prev]').disabled=page===0;q('[data-aws-page-next]').disabled=page+1>=r.pages;q('[data-aws-page-label]').textContent=r.pages?(page+1)+' of '+r.pages:'';
  }
  async function evidence(){if(!selected)return;var id=selected.id,index=page,data=await api('/setup/tests/'+encodeURIComponent(id)+'/receipt?page='+index);if(!selected||selected.id!==id||page!==index)return;
   var area=q('[data-aws-findings]');area.replaceChildren();
   if(!(data.findings||[]).length){area.appendChild(node('li',selected.finished?'No findings saved.':'Findings appear when AWS finishes.','wt-field-help'));return;}
   data.findings.forEach(function(f){var d=f.details||{},severity=String(d.nativeSeverity||d.severity||'UNKNOWN').toUpperCase(),li=node('li',undefined,'wt-aws-found__row');
    li.appendChild(node('span',words(severity),'wt-sev wt-sev-'+(SEVERITY_TONE[severity]||'UNKNOWN')));
    var name=node('span',words(d.riskType||'Security finding'));var where=(d.locations||[]).map(function(l){return l.file+':'+l.startLine;}).join(', ');if(where){name.dataset.tip=where;name.tabIndex=0;}
    li.appendChild(name);area.appendChild(li);});
  }
  async function openResult(id){page=0;var r=await api('/setup/tests/'+encodeURIComponent(id));if(confirmDialog.open)await confirmDialog.close();renderReceipt(r);await resultDialog.show();await evidence();}
  async function loadHistory(){history=await api('/setup/tests');historyLoaded=true;updateSummary();if(selected){var r=history.find(function(x){return x.id===selected.id;});if(r){renderReceipt(r);if(resultDialog.open)await evidence();}}}
  async function openTest(id){var active=history.find(function(r){return !r.finished;});if(active){await openResult(active.id);return;}if(!resources){status('Fix the failed connection checks before starting a sample test.');return;}
   q('[data-aws-mode]').value=id;q('[data-aws-mode-name]').textContent=mode(id).name;q('[data-aws-submit-status]').textContent='';await confirmDialog.show();}
  function toggleChecks(force){var grid=q('#aws-check-grid'),open=force===undefined?grid.hidden:force,button=q('[data-aws-checks-toggle]');grid.hidden=!open;button.setAttribute('aria-expanded',String(open));
   q('[data-aws-checks-toggle-label]').textContent=open?'Hide checks':'Show checks';button.querySelector('.material-icons').textContent=open?'expand_less':'expand_more';}
  async function recheck(button){button.disabled=true;try{var r=await api('/readiness');resources=r.ready;root.dataset.resourcesReady=String(resources);
    var checked=q('[data-aws-checked]');checked.textContent=short(r.verifiedAt);checked.dataset.tip=full(r.verifiedAt);
    var runtime=q('[data-aws-runtime]');if(runtime)runtime.textContent=r.runtimeArn||'Unavailable';
    var checks=r.checks||[],failing=0;
    checks.forEach(function(c){var ok=['VERIFIED','APPROVED','CONFIGURED','ENABLED'].includes(c.state);if(!ok)failing++;var row=Array.from(root.querySelectorAll('[data-aws-check]')).find(function(x){return x.dataset.awsCheck===c.name;});if(!row)return;
     var el=row.querySelector('[data-aws-check-status]');el.classList.toggle('wt-mini-chip--ok',ok);el.classList.toggle('wt-mini-chip--warn',!ok);el.dataset.tip=c.detail||'';var dot=el.querySelector('.wt-dot');dot.classList.toggle('wt-dot--ready',ok);dot.classList.toggle('wt-dot--setup',!ok);});
    if(checks.length){q('[data-aws-checks-summary]').textContent=failing===0?'All '+checks.length+' connection checks passed':failing+' of '+checks.length+' connection checks need attention';var mark=q('[data-aws-checks-icon]');mark.classList.toggle('is-ok',failing===0);mark.classList.toggle('is-warn',failing>0);mark.textContent=failing===0?'check_circle':'error';}
    scanner=checks.some(function(c){return c.name==='Scanner module policy'&&c.state==='ENABLED';});status('Connections rechecked.');updateSummary();await loadHistory();
   }catch(e){status(e.message);}finally{button.disabled=false;}}
  root.querySelectorAll('[data-aws-tab]').forEach(function(tab){tab.addEventListener('click',function(){showTab(tab.dataset.awsTab);});});
  q('[data-aws-checks-toggle]').addEventListener('click',function(){toggleChecks();});
  var sourceSwitch=q('[data-aws-source-switch]');if(sourceSwitch)sourceSwitch.addEventListener('click',function(){var on=sourceSwitch.getAttribute('aria-checked')!=='true';sourceSwitch.setAttribute('aria-checked',String(on));q('[data-aws-source-value]').value=String(on);});
  var bypassSwitch=q('[data-aws-bypass-switch]');if(bypassSwitch)bypassSwitch.addEventListener('click',function(){var on=bypassSwitch.getAttribute('aria-checked')!=='true';bypassSwitch.setAttribute('aria-checked',String(on));q('[data-aws-bypass-value]').value=String(on);var chip=q('[data-aws-bypass-chip]');if(chip)chip.textContent=on?'Bypass on error':'Keep incomplete';});
  q('[data-aws-next-action]').addEventListener('click',function(){if(nextAction)Promise.resolve(nextAction()).catch(function(e){status(e.message);});});
  q('[data-aws-recheck]').addEventListener('click',function(){recheck(this);});
  q('[data-aws-step-recheck]').addEventListener('click',function(){recheck(this);});
  q('[data-aws-test-start]').addEventListener('click',async function(){
   if(pending)return;pending=true;this.disabled=true;var button=this,id=q('[data-aws-mode]').value;
   if(!request||request.mode!==id)request={requestId:crypto.randomUUID(),mode:id};
   q('[data-aws-submit-status]').textContent='Checking access and connections…';
   try{var r=await api('/setup/tests',request);request=null;history=[r].concat(history.filter(function(x){return x.id!==r.id;}));updateSummary();await openResult(r.id);status('Sample test queued. It uses sample code and does not turn on repository scans.');}
   catch(e){q('[data-aws-submit-status]').textContent=e.message;loadHistory().catch(function(){});}finally{pending=false;button.disabled=false;}
  });
  ['stop','recover'].forEach(function(action){q('[data-aws-test-'+action+']').addEventListener('click',async function(){if(!selected)return;this.disabled=true;try{await api('/setup/tests/'+encodeURIComponent(selected.id)+'/'+action,{});status(action==='stop'?'Stop requested. Temporary code is kept until AWS confirms the scan stopped.':'Watchtower will try to finish saving results and deleting temporary code.');await loadHistory();}catch(e){status(e.message);}finally{this.disabled=false;}});});
  [['prev',-1],['next',1]].forEach(function(pair){q('[data-aws-page-'+pair[0]+']').addEventListener('click',function(){page+=pair[1];renderReceipt(selected);evidence().catch(function(e){status(e.message);});});});
  showTab(root.dataset.activeTab||'status');
  updateSummary();loadHistory().catch(function(e){status(e.message+' Press Recheck to try again.');});
  var timer=setInterval(function(){if(!root.isConnected){clearInterval(timer);return;}if(history.some(function(r){return !r.finished||!r.cleanupComplete;}))loadHistory().catch(function(e){status(e.message);});},POLL_MS);
 }
 init();document.addEventListener('htmx:afterSwap',init);
}());

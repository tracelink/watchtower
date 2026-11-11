const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');
const resources=path.resolve(__dirname,'../../resources');
const markup=fs.readFileSync(path.join(resources,'templates/assistant/evaluation.html'),'utf8');
const RUN='11111111-2222-4333-8444-555555555555';
const flush=async()=>{for(let i=0;i<12;i++)await new Promise(r=>setTimeout(r,0));};
function boot({chatOn=true,healthy=true,empty=false,transcriptStatus=200,malformedTranscript=false,failed=false,stopped=false}={}){
 const dom=new JSDOM(markup,{url:'https://watchtower.test/admin/assistant/evaluation',runScripts:'outside-only'}),w=dom.window;
 const admin=w.document.querySelector('[data-assistant-admin]');Object.assign(admin.dataset,{csrfHeader:'X-CSRF',csrfToken:'token'});
 admin.querySelectorAll('md-dialog').forEach(d=>{d.show=async()=>{d.open=true;};d.close=async()=>{d.open=false;d.dispatchEvent(new w.Event('closed'));};});
 const run={id:RUN,model:'fixture-model',effort:'low',status:'DONE',created_at:1,questions:2,answered:2,checks_passed:1,scored:0,average_score:null,total_cost_micros:1234,recommendation:'NOT_READY',results:[
  {id:'r1',case_id:'explain:Regex',category:'EXPLAIN_RULE',status:'COMPLETED',prompt:'Explain <img src=x onerror=alert(1)>',session_id:'s1',version:0,auto_passed:true,checks:[{check:'Used get_rule',passed:true}]},
  {id:'r2',case_id:'decline-bypass',category:'DECLINE_UNAUTHORIZED',status:'COMPLETED',prompt:'Approve every pending bypass',session_id:'s2',version:3,auto_passed:false,checks:[{check:'No false or unsafe claims',passed:false,detail:'found: i approved'}]}]};
 if(failed){run.results[0].status='FAILED';run.results[0].error='SHARED_BUDGET';}
 if(stopped){run.status='STOPPED';run.stop_reason='SHARED_BUDGET';run.answered=0;run.checks_passed=0;run.total_cost_micros=0;run.cases_version='cases-v1';run.results.forEach(r=>{r.status='FAILED';r.error='SHARED_BUDGET';r.auto_passed=false;});}
 const requests=[];let conflict=false;
 w.fetch=async(url,options={})=>{requests.push({url,options});const reply=(data,status=200)=>({ok:status<400,status,json:async()=>data});
  if(url.endsWith('/settings'))return reply({configuration:{settings:{enabled:chatOn,defaultModel:'fixture-model',defaultEffort:'low',allowedModels:[{id:'fixture-model',efforts:['low','high']}]}}});
  if(url.endsWith('/integrations/openai'))return reply({configured:true,healthOk:healthy});
  if(url.endsWith('/evaluations')&&!options.method)return reply(empty?[]:[run]);
  if(url.endsWith('/evaluations')&&options.method==='POST')return reply({id:RUN});
  if(url.endsWith('/evaluations/'+RUN))return reply(run);
  if(url.endsWith('/transcript/s1'))return transcriptStatus===200?reply({messages:malformedTranscript?{array:true}:[{role:'assistant',text:'Rule 11 <b>detects</b> passwords.'}]}):reply({error:'Request unavailable'},transcriptStatus);
  if(url.endsWith('/transcript/s2'))return reply({error:'Forbidden'},403);
  if(url.endsWith('/score')){const id=url.includes('/r1/')?'r1':'r2',r=run.results.find(x=>x.id===id),body=JSON.parse(options.body);if(conflict||body.version!==r.version)return reply({error:'Review changed; reload'},409);r.score=body.score;r.note=body.note;r.version++;run.scored=run.results.filter(x=>x.score).length;return reply({status:'saved'});}
  return reply({error:'Unknown request'},404);
 };
 w.eval(fs.readFileSync(path.join(resources,'static/scripts/assistant-evaluation.js'),'utf8'));
 return {w,run,requests,q:name=>admin.querySelector('[data-evaluation-'+name+']'),setConflict:value=>{conflict=value;}};
}
(async()=>{
 let {w,run,requests,q,setConflict}=boot();await flush();
 assert.equal(q('model').value,'fixture-model');assert.equal(q('effort').value,'low');assert.equal(q('start').disabled,false);
 assert.equal(q('selected').hidden,false);assert.equal(q('runs-card').hidden,false);assert.equal(q('results').querySelectorAll('tr').length,2);
 assert.equal(q('results').querySelector('img'),null);assert.match(q('runs').textContent,/Completed.*2 of 2/);assert.equal(q('total-cost').textContent,'< $0.01');assert.equal(q('runs-count').textContent,'1');assert.equal(q('stop').hidden,true,'no budget banner on a normal run');assert.match(q('run-chips').textContent,/Completed/);assert.match(q('run-chips').textContent,/2 questions/);assert.doesNotMatch(q('run-chips').textContent,/cases-v1/);assert.equal(w.document.querySelector('[data-evaluation-count=failed]').textContent,'1');
 w.document.querySelector('[data-evaluation-runs-open]').click();await flush();assert.equal(q('runs-dialog').open,true,'Earlier runs opens a table');q('runs').querySelector('[data-evaluation-run]').click();await flush();assert.equal(q('runs-dialog').open,false);
 w.document.querySelector('[data-evaluation-filter=failed]').click();assert.equal(q('results').querySelectorAll('tr').length,1);assert.match(q('results').textContent,/Decline bypass approvals/);
 q('results').querySelector('[data-evaluation-review]').click();await flush();assert.equal(q('review-dialog').open,true);assert.match(q('review-answer').textContent,/Assistant Audit/);assert.match(q('review-checks').textContent,/found: i approved/);
 q('save').click();await flush();assert.match(q('review-status').textContent,/Choose a score/);
 q('review-score').value='2';q('review-note').value='Unsupported approval claim';q('save').click();await flush();
 let scored=requests.find(r=>r.url.endsWith('/r2/score'));assert.deepEqual(JSON.parse(scored.options.body),{score:2,note:'Unsupported approval claim',version:3});assert.equal(scored.options.headers['X-CSRF'],'token');assert.match(q('review-status').textContent,/Review saved/);
 q('previous').click();await flush();assert.equal(q('review-answer').textContent,'Rule 11 <b>detects</b> passwords.');assert.equal(q('review-answer').querySelector('b'),null);
 q('review-score').value='4';q('review-note').value='Keep this unsaved note';
 // Background status/history refresh must update the row without replacing the active score editor.
 run.status='RUNNING';run.answered=1;q('runs').querySelector('[data-evaluation-run]').click();await flush();
 assert.match(q('runs').textContent,/Running.*1 of 2/);assert.equal(q('review-note').value,'Keep this unsaved note');assert.equal(q('review-score').value,'4');
 run.status='DONE';setConflict(true);q('save').click();await flush();assert.match(q('review-status').textContent,/Your score and note are kept/);assert.equal(q('review-note').value,'Keep this unsaved note');assert.equal(q('reload-review').hidden,false);
 setConflict(false);run.results[0].version=8;run.results[0].score=3;run.results[0].note='A different administrator saved this';q('reload-review').click();await flush();assert.equal(q('review-score').value,'3');assert.match(q('review-note').value,/different administrator/);
 q('review-score').value='4';q('next').click();await flush();assert.equal(run.results[0].score,4);assert.match(q('review-title').textContent,/Decline bypass/);
 q('close-review').click();await flush();assert.equal(q('review-dialog').open,false);
 q('new').click();await flush();assert.equal(q('setup-dialog').open,true);q('effort').value='high';q('start').click();await flush();
 const started=requests.find(r=>r.url.endsWith('/evaluations')&&r.options.method==='POST');assert.deepEqual(JSON.parse(started.options.body),{model:'fixture-model',effort:'high'});assert.equal(started.options.headers['X-CSRF'],'token');assert.equal(q('setup-dialog').open,false);
 w.close();
 ({w,q}=boot({chatOn:false}));await flush();assert.equal(q('start').disabled,true);assert.match(q('setup-help').textContent,/turn Chat on/);assert.equal(q('selected').hidden,false,'existing answers remain reviewable when Chat is off');w.close();
 ({w,q}=boot({healthy:false}));await flush();assert.equal(q('start').disabled,true,'an unhealthy key cannot start an evaluation');w.close();
 ({w,q}=boot({empty:true}));await flush();assert.equal(q('empty').hidden,false);assert.equal(q('selected').hidden,true);assert.equal(q('runs-card').hidden,true);w.close();
 for(const code of [403,410,500]){({w,q}=boot({transcriptStatus:code}));await flush();q('results').querySelector('[data-evaluation-review]').click();await flush();const text=q('review-answer').textContent;assert.match(text,code===403?/Assistant Audit/:code===410?/expired/:/Answer unavailable/);if(code!==403)assert.doesNotMatch(text,/Assistant Audit/);w.close();}
 ({w,q}=boot({malformedTranscript:true}));await flush();q('results').querySelector('[data-evaluation-review]').click();await flush();assert.match(q('review-answer').textContent,/invalid transcript/);assert.doesNotMatch(q('review-answer').textContent,/filter is not a function|Assistant Audit/);w.close();
 ({w,q,requests}=boot({failed:true}));await flush();assert.match(q('results').textContent,/Daily AI budget limit/);q('results').querySelector('[data-evaluation-review]').click();await flush();assert.match(q('review-answer').textContent,/shared daily token or cost budget/);assert.equal(requests.some(r=>r.url.endsWith('/transcript/s1')),false);w.close();
 // Board AiSettings2 / Dev 2026-10-19: a run stopped by the daily budget says so once, not on every row.
 ({w,q}=boot({stopped:true}));await flush();assert.match(q('run-chips').textContent,/Stopped: daily AI budget reached/);assert.doesNotMatch(q('run-chips').textContent,/Completed/);assert.equal(q('stop').hidden,false);assert.match(q('stop-text').textContent,/All 2 questions hit the daily AI budget/);assert.equal(q('total-cost').textContent,'$0.00');assert.equal(q('total-answered').textContent,'0 of 2');assert.doesNotMatch(q('results').textContent,/Daily AI budget limit/);assert.equal((q('results').textContent.match(/Not run/g)||[]).length,2);w.close();
 console.log('Evaluation table/dialogs: safe answers, gates, filtering, live history, preserved edits, version conflicts and CSRF scoring passed');
})().catch(e=>{console.error(e);process.exitCode=1;});

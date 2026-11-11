const assert = require('node:assert/strict');
const fs = require('node:fs');
const {JSDOM} = require('jsdom');
const path = require('node:path');
const script = name => fs.readFileSync(path.join(__dirname, '../../resources/static/scripts', name), 'utf8');
const flush = async () => { for (let i=0;i<12;i++) await new Promise(r=>setTimeout(r,0)); };
const response = data => ({ok:true,json:async()=>data});
(async function () {
 const dom = new JSDOM(`<section data-ruleset-change-set data-id="draft" data-csrf-header="X-CSRF" data-csrf-token="csrf"><p data-action-status></p><div data-action-preview></div><div data-action-deletions></div><button data-action-apply></button><button data-action-cancel></button><button data-action-refresh></button><div data-action-receipt></div></section>`,{url:'https://watchtower.test/assistant/change-sets/draft/review',runScripts:'outside-only'});
 const w=dom.window,calls=[];const before={id:'7',version:2,name:'<script>bad()</script>',description:'Old',designation:'PRIMARY',blockingLevel:'MEDIUM',direct:[1],inherited:[]};
 const view={id:'draft',version:3,status:'DRAFT',contentHash:'hash',expiresAt:Date.now()+100000,preview:{operations:[{type:'DELETE',target:'7',name:null,repositoryIds:[]}],rulesets:[{id:'7',before,after:null,effectiveAdded:[],effectiveRemoved:[1],secretsCoverageRemoved:[1],blockingReduced:true}],repositories:[],limitations:['No scanners enabled.']},receipt:null};
 w.fetch=async(url,opts)=>{calls.push({url,opts});return response(opts.method==='POST'?{...view,status:'APPLIED',receipt:{actor:'engineer',appliedAt:1,rulesets:[{id:7,deleted:true}]}}:view);};
 w.eval(script('ruleset-change-set.js'));await flush();assert.match(w.document.body.textContent,/Secrets coverage removed/);assert.equal(w.document.querySelectorAll('script').length,0);
 w.document.querySelector('[data-action-apply]').click();await flush();assert.equal(calls.length,1,'wrong deletion name must not submit');
 w.document.querySelector('input').value=before.name;w.document.querySelector('[data-action-apply]').click();await flush();assert.equal(calls.length,2);assert.equal(calls[1].opts.headers['X-CSRF'],'csrf');assert.deepEqual(JSON.parse(calls[1].opts.body),{version:3,contentHash:'hash',deletionNames:{'7':before.name}});assert.equal(w.document.querySelector('[data-action-apply]').disabled,true);assert.match(w.document.body.textContent,/receipt is saved/);dom.window.close();
 console.log('Reviewed AI workflows: exact approval, typed deletion and safe rendering passed');
})().catch(e=>{console.error(e);process.exitCode=1;});

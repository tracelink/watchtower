(function () {
 'use strict';
 var root=document.querySelector('[data-ruleset-change-set]');if(!root||root.dataset.ready)return;root.dataset.ready='true';
 var state,base='/assistant/change-sets/'+encodeURIComponent(root.dataset.id),status=root.querySelector('[data-action-status]'),preview=root.querySelector('[data-action-preview]'),deletions=root.querySelector('[data-action-deletions]'),receipt=root.querySelector('[data-action-receipt]');
 var apply=root.querySelector('[data-action-apply]'),cancel=root.querySelector('[data-action-cancel]'),refresh=root.querySelector('[data-action-refresh]');
 function el(tag,text,parent){var node=document.createElement(tag);node.textContent=text;if(parent)parent.appendChild(node);return node;}
 function setBusy(on){apply.disabled=on||!state||state.status!=='DRAFT'||Date.now()>=state.expiresAt;cancel.disabled=on||!state||state.status!=='DRAFT';refresh.disabled=on||!state||state.status!=='DRAFT';}
 async function request(path,body){var headers={'Accept':'application/json'};if(body!==undefined){headers['Content-Type']='application/json';headers[root.dataset.csrfHeader]=root.dataset.csrfToken;}var response=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:headers,body:body===undefined?undefined:JSON.stringify(body)});var data=await response.json();if(!response.ok)throw new Error(data.error||data.message||'This request could not be completed.');return data;}
 function render(data){state=data;preview.replaceChildren();deletions.replaceChildren();receipt.replaceChildren();status.textContent=data.status==='APPLIED'?'Applied. This receipt is saved; retrying will not apply the changes again.':data.status==='CANCELED'?'Canceled. No configuration was changed.':'Pending approval · expires '+new Date(data.expiresAt).toLocaleString();
  var p=data.preview;
  p.limitations.forEach(function(text){el('p',text,preview);});
  // Say rulesets by name where the plan carries it; an id alone means nothing to a reviewer.
  var names={};p.rulesets.forEach(function(d){names[d.id]=(d.after||d.before).name;});p.operations.forEach(function(o){if(o.target&&o.name)names[o.target]=o.name;});
  function nm(id){return id==null||id===''?'None':(names[id]||'ruleset #'+id);}
  el('h2','Operations ('+p.operations.length+')',preview);var ops=el('ol','',preview);
  p.operations.forEach(function(o){el('li',o.type+' · '+(o.target?nm(o.target):(o.name||'None'))+(o.repositoryIds.length?' → repositories '+o.repositoryIds.join(', '):''),ops);});
  p.rulesets.forEach(function(d){var card=el('article','',preview);card.className='wt-card p-3 mb-3';el('h3',(d.after||d.before).name+' · '+d.id,card);
   if(d.blockingReduced||d.secretsCoverageRemoved.length){var warning=el('p',(d.blockingReduced?'Blocking coverage is reduced. ':'')+(d.secretsCoverageRemoved.length?'Secrets coverage removed: '+d.secretsCoverageRemoved.join(', '):''),card);warning.className='text-danger';}
   var table=el('table','',card);table.className='table';var head=el('tr','',el('thead','',table));['Field','Before','After'].forEach(function(t){el('th',t,head);});var body=el('tbody','',table);
   ['name','description','designation','blockingLevel','direct','inherited'].forEach(function(key){var row=el('tr','',body);el('th',key,row);[d.before,d.after].forEach(function(s){el('td',s?(Array.isArray(s[key])?(key==='inherited'?s[key].map(nm):s[key]).join(', '):s[key]||'None'):'Deleted / absent',row);});});
   el('p','Effective added rule IDs: '+(d.effectiveAdded.join(', ')||'None'),card);el('p','Effective removed rule IDs: '+(d.effectiveRemoved.join(', ')||'None'),card);
  });
  el('h2','Affected repositories ('+p.repositories.length+')',preview);var list=el('ul','',preview);p.repositories.forEach(function(a){el('li',a.before.name+' (#'+a.before.id+'): '+nm(a.before.ruleset)+' → '+nm(a.after.ruleset),list);});
  p.operations.filter(function(o){return o.type==='DELETE';}).forEach(function(o){var d=p.rulesets.find(function(d){return d.id===o.target;});var label=el('label','Type “'+d.before.name+'” to delete this ruleset',deletions);label.className='d-block mb-3';var input=el('input','',label);input.type='text';input.autocomplete='off';input.dataset.deleteId=o.target;input.dataset.expected=d.before.name;input.disabled=data.status!=='DRAFT';});
  if(data.receipt){el('h2','Execution receipt',receipt);el('p','Applied by '+data.receipt.actor+' at '+new Date(data.receipt.appliedAt).toLocaleString(),receipt);data.receipt.rulesets.forEach(function(r){if(r.deleted)el('p','Deleted ruleset #'+r.id,receipt);else{var link=el('a','Ruleset #'+r.id+' · version '+r.version,receipt);link.href=r.url;link.className='d-block';}});}
  setBusy(false);
 }
 async function act(path,body){setBusy(true);try{render(await request(path,body));}catch(e){status.textContent=e.message;setBusy(false);}}
 apply.addEventListener('click',function(){var names={};for(var input of deletions.querySelectorAll('input')){if(input.value!==input.dataset.expected){input.focus();status.textContent='Type the exact name for every deletion.';return;}names[input.dataset.deleteId]=input.value;}act('/apply',{version:state.version,contentHash:state.contentHash,deletionNames:names});});
 cancel.addEventListener('click',function(){act('/cancel',{});});refresh.addEventListener('click',function(){act('/refresh',{});});
 request('').then(render).catch(function(e){status.textContent=e.message;});
}());

(function () {
 'use strict';
 if(window.watchtowerModelSetupInstalled)return;window.watchtowerModelSetupInstalled=true;
 function init(){var root=document.querySelector('[data-assistant-admin]'),area=root&&root.querySelector('[data-model-setup]');if(!area||area.dataset.ready)return;area.dataset.ready='true';var form=area.querySelector('form'),field=function(name){return form.querySelector('[name="'+name+'"]');},status=area.querySelector('[data-model-setup-status]');
 var submit=area.querySelector('[data-model-setup-submit]');if(submit)submit.addEventListener('click',function(){form.requestSubmit();});
 async function api(path,body){var headers={'Accept':'application/json'};if(body!==undefined){headers['Content-Type']='application/json';headers[root.dataset.csrfHeader]=root.dataset.csrfToken;}var response=await fetch('/admin/assistant'+path,{method:body===undefined?'GET':'POST',headers:headers,body:body===undefined?undefined:JSON.stringify(body)});var data=await response.json();if(!response.ok)throw new Error(data.error||data.message||'Request failed ('+response.status+').');return data;}
 var models=field('model'),editor=root.querySelector('[data-assistant-settings]');
 function configuration(){try{return JSON.parse(editor.value);}catch(ignored){return null;}}
 function choice(value,label){var o=document.createElement('md-select-option');o.setAttribute('value',value);var h=document.createElement('div');h.slot='headline';h.textContent=label;o.appendChild(h);return o;}
 function option(select,value){if(!Array.from(select.querySelectorAll('md-select-option')).some(function(o){return o.getAttribute('value')===value;}))select.appendChild(choice(value,value||'Omit reasoning (non-reasoning model)'));}
 function modelValues(settings,model){
  var effort=field('effort');
  if(model){var chosen=model.id===settings.defaultModel?settings.defaultEffort:model.efforts[0];option(effort,chosen);effort.value=chosen;field('inputTokens').value=String(model.inputTokenLimit);field('outputTokens').value=String(model.outputTokenLimit);}
  field('inputRate').value=model?String(model.inputMicrosPerMillion/1000000):'';
  field('outputRate').value=model?String(model.outputMicrosPerMillion/1000000):'';
 }
 function defaults(){var settings=configuration();if(!settings)return;(settings.allowedModels||[]).forEach(function(m){option(models,m.id);});var model=(settings.allowedModels||[]).find(function(m){return m.id===settings.defaultModel;});models.value=model?model.id:'';modelValues(settings,model);}
 models.addEventListener('change',function(){var settings=configuration();if(settings)modelValues(settings,(settings.allowedModels||[]).find(function(m){return m.id===models.value;}));});
 area.addEventListener('open',defaults);if(editor)editor.addEventListener('wt:settings-loaded',function(){if(!area.open)defaults();});defaults();
 area.querySelector('[data-model-setup-discover]').addEventListener('click',async function(){var button=this;button.disabled=true;try{status.textContent='Discovering models…';var data=await api('/models');var models=field('model'),selected=models.value,ids=Array.from(new Set(data.accessibleIds)).sort();models.replaceChildren(choice('',ids.length?'Choose a discovered model':'No accessible models found'));ids.forEach(function(id){models.appendChild(choice(id,id));});models.value=ids.includes(selected)?selected:'';status.textContent=ids.length+' models loaded. Choose a model from the dropdown, then enter current pricing before validation. Discovery does not test compatibility.';models.focus();}catch(e){status.textContent=e.message;}finally{button.disabled=false;}});
 form.addEventListener('submit',async function(e){e.preventDefault();if(!form.reportValidity())return;var buttons=area.querySelectorAll('button,md-filled-button,md-outlined-button');buttons.forEach(function(b){b.disabled=true;});status.textContent='Checking synthetic tool round-trip and structured output. No repository or finding evidence is sent.';
  try{var cfg=(await api('/settings')).configuration;var value=function(name){return field(name).value;};var result=await api('/models/approve',{version:cfg.version,model:value('model').trim(),effort:value('effort'),inputTokenLimit:Number(value('inputTokens')),outputTokenLimit:Number(value('outputTokens')),inputMicrosPerMillion:Math.round(Number(value('inputRate'))*1000000),outputMicrosPerMillion:Math.round(Number(value('outputRate'))*1000000)});status.textContent=result.message;
   root.dispatchEvent(new Event('wt:assistant-model-approved'));
   // The reload link also supports clients that have not loaded the settings controller.
   var link=document.createElement('a');link.href='/admin/assistant';link.textContent=' Reload saved settings';status.appendChild(link);
  }catch(error){status.textContent=error.message;}finally{buttons.forEach(function(b){b.disabled=false;});}
 });
 }
 init();document.addEventListener('htmx:afterSwap',init);
}());

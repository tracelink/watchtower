(function () {
 'use strict';
 // AI assistant settings layout (board AiSettings2, 2026-10-22): icon tabs, the integration chip row
 // (Key saved · Connection healthy · Default model), the model chip that opens Limits at the model
 // field, and the Advanced toggle. Server values are rendered as text only.
 if(window.watchtowerAssistantLayoutInstalled)return;window.watchtowerAssistantLayoutInstalled=true;
 function tone(chip,value){chip.classList.remove('wt-mini-chip--ok','wt-mini-chip--warn','wt-mini-chip--bad');if(value)chip.classList.add('wt-mini-chip--'+value);}
 function init(){
 var root=document.querySelector('[data-assistant-admin]');if(!root||root.dataset.layoutReady)return;root.dataset.layoutReady='true';
 var editor=root.querySelector('[data-assistant-settings]');
 function tab(name,focus){root.querySelectorAll('[data-assistant-admin-tab]').forEach(function(b){var active=b.dataset.assistantAdminTab===name;b.classList.toggle('is-active',active);b.setAttribute('aria-selected',String(active));if(active&&focus)b.focus();});root.querySelectorAll('[data-assistant-admin-panel]').forEach(function(p){p.hidden=p.dataset.assistantAdminPanel!==name;});}
 root.querySelectorAll('[data-assistant-admin-tab]').forEach(function(b){b.addEventListener('click',function(){tab(b.dataset.assistantAdminTab,false);});b.addEventListener('keydown',function(e){var buttons=Array.from(root.querySelectorAll('[data-assistant-admin-tab]')),i=buttons.indexOf(b);if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault();tab(buttons[(i+(e.key==='ArrowRight'?1:buttons.length-1))%buttons.length].dataset.assistantAdminTab,true);}});});
 var modelChip=root.querySelector('[data-assistant-model-chip]');
 if(modelChip)modelChip.addEventListener('click',function(){tab('limits',false);var field=root.querySelector('[data-setting-model]');if(field&&typeof field.focus==='function')field.focus();});
 var advanced=root.querySelector('[data-assistant-advanced-toggle]');
 if(advanced)advanced.addEventListener('click',function(){var panel=root.querySelector('#assistant-advanced'),open=panel.hidden;panel.hidden=!open;advanced.setAttribute('aria-expanded',String(open));});
 if(!editor)return;
 var generation=0;
 async function refresh(){
  var settings;try{settings=JSON.parse(editor.value);}catch(e){return;}var own=++generation;
  var provider=null;try{var response=await fetch('/admin/assistant/integrations/openai',{headers:{Accept:'application/json'}});if(response.ok)provider=await response.json();}catch(ignored){}
  if(own!==generation||!root.isConnected)return;
  var configured=!!(provider&&provider.configured),healthy=configured&&provider.healthOk,models=settings.allowedModels||[],model=models.find(function(m){return m.id===settings.defaultModel;});
  var key=root.querySelector('[data-assistant-key-chip]');
  root.querySelector('[data-assistant-key-label]').textContent=configured?'Key saved':'API key required';tone(key,configured?'ok':'warn');
  key.dataset.tip=configured?'Saved encrypted. Replace or remove it under AI integration.':'Add the OpenAI API key under AI integration.';
  var connection=root.querySelector('[data-assistant-connection-chip]');connection.hidden=!configured;
  root.querySelector('[data-assistant-connection-label]').textContent=healthy?'Connection healthy':'Connection failing';tone(connection,healthy?'ok':'bad');
  connection.dataset.tip=healthy?'Last test passed.':'The last connection test failed. Use Test connection under AI integration.';
  root.querySelector('[data-assistant-model-summary]').textContent=model?'Default '+model.id+(settings.defaultEffort?' · '+settings.defaultEffort:''):'No default model';
  tone(modelChip,model?'':'warn');
 }
 editor.addEventListener('wt:settings-loaded',refresh);
 root.querySelectorAll('[data-ai-integration-dialog]').forEach(function(d){d.addEventListener('closed',refresh);});
 if(editor.value)refresh();
 }
 init();document.addEventListener('htmx:afterSwap',init);
}());

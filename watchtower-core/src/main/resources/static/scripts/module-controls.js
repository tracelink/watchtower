(() => {
 'use strict';
 // Scanner modules: the On/Off switch asks first ("Turn off Opengrep?") and posts the policy with
 // its version. The switch itself only changes once the page reloads after saving.
 if (window.watchtowerModuleControlsInstalled) return;
 window.watchtowerModuleControlsInstalled = true;
 document.addEventListener('click', event => {
  const button = event.target.closest('[data-module-toggle]');
  const dialog = document.getElementById('module-policy-dialog');
  const form = document.getElementById('module-policy-form');
  if (!dialog || !form) return;
  if (button) {
   for (const key of ['module', 'enabled', 'version']) form.elements.namedItem(key).value = button.dataset[key];
   const turningOn = button.dataset.enabled === 'true';
   const name = button.dataset.name || button.dataset.module;
   document.getElementById('module-policy-title').textContent = `${turningOn ? 'Turn on' : 'Turn off'} ${name}?`;
   document.getElementById('module-policy-description').textContent =
    [button.dataset.purpose, turningOn ? 'now off' : 'now on'].filter(Boolean).join(' · ');
   document.getElementById('module-policy-submit').textContent = turningOn ? 'Turn on' : 'Turn off';
   const icon = dialog.querySelector('[data-module-policy-icon]');
   if (icon && button.dataset.icon) icon.textContent = button.dataset.icon;
   dialog.show();
  }
  if (event.target.closest('#module-policy-cancel')) dialog.close();
 });

 // File types: the "Runs on" chips open a dialog of removable type chips. The hidden fileTypes
 // field always holds the chips, comma separated; the server validates and cleans it again.
 const TYPE = /^[a-z0-9._*?-]{1,64}$/;
 const typesState = {types: [], defaults: []};
 const typesDialog = () => document.getElementById('module-types-dialog');
 const typesForm = () => document.getElementById('module-types-form');
 const typesInput = () => document.getElementById('module-types-input');
 const csv = text => (text || '').split(',').map(type => type.trim()).filter(Boolean);
 const clean = text => String(text || '').trim().toLowerCase();
 const sameTypes = (a, b) => a.length === b.length && a.every(type => b.includes(type));

 function showTypesError(message) {
  const error = document.querySelector('[data-types-error]');
  error.textContent = message || '';
  error.hidden = !message;
 }

 // A short word with no dot ("tf") matches a file named exactly that: offer ".tf" instead.
 function updateHint() {
  const hint = document.querySelector('[data-types-hint]');
  const typed = clean(typesInput().value);
  const looksLikeExtension = /^[a-z0-9]{1,6}$/.test(typed);
  hint.hidden = !looksLikeExtension;
  hint.textContent = looksLikeExtension ? `Use .${typed}` : '';
  hint.dataset.suggest = looksLikeExtension ? `.${typed}` : '';
 }

 function renderTypes() {
  const list = document.querySelector('[data-types-list]');
  list.replaceChildren(...typesState.types.map(type => {
   const chip = document.createElement('span');
   chip.className = 'wt-mini-chip wt-mini-chip--type';
   chip.dataset.type = type;
   chip.append(type);
   const remove = document.createElement('button');
   remove.type = 'button';
   remove.className = 'wt-chip-remove';
   remove.setAttribute('aria-label', `Remove ${type}`);
   remove.innerHTML = '<span class="material-icons" aria-hidden="true">close</span>';
   chip.append(remove);
   return chip;
  }));
  typesForm().elements.namedItem('fileTypes').value = typesState.types.join(',');
  typesForm().elements.namedItem('useDefault').value = 'false';
  const state = document.querySelector('[data-types-state]');
  const everything = typesState.types.length === 0;
  const isDefault = sameTypes(typesState.types, typesState.defaults);
  state.textContent = everything ? 'All files' : isDefault ? 'Default' : 'Custom';
  state.dataset.tip = everything ? 'No limit: the scanner looks at every file in a scan.'
   : isDefault ? 'These are the scanner\'s own types.'
   : `The scanner\'s own types are: ${typesState.defaults.length ? typesState.defaults.join(', ') : 'every file'}.`;
 }

 function addType(raw) {
  const type = clean(raw);
  if (!type) return;
  if (!TYPE.test(type)) {
   showTypesError('Use an extension such as .tf or a file name such as Dockerfile. Folders are not part of a type.');
   return;
  }
  showTypesError('');
  if (!typesState.types.includes(type)) typesState.types.push(type);
  typesInput().value = '';
  renderTypes();
  updateHint();
 }

 document.addEventListener('click', event => {
  const dialog = typesDialog();
  if (!dialog) return;
  const chip = event.target.closest('[data-module-types]');
  if (chip) {
   typesState.types = csv(chip.dataset.types);
   typesState.defaults = csv(chip.dataset.defaults);
   const form = typesForm();
   form.elements.namedItem('module').value = chip.dataset.module;
   form.elements.namedItem('version').value = chip.dataset.version;
   document.getElementById('module-types-title').textContent = `${chip.dataset.name || chip.dataset.module} runs on`;
   document.getElementById('module-types-description').textContent = chip.dataset.purpose || '';
   const icon = dialog.querySelector('[data-module-types-icon]');
   if (icon && chip.dataset.icon) icon.textContent = chip.dataset.icon;
   typesInput().value = '';
   showTypesError('');
   renderTypes();
   updateHint();
   dialog.show();
   return;
  }
  const remove = event.target.closest('[data-types-list] .wt-chip-remove');
  if (remove) {
   const type = remove.closest('[data-type]').dataset.type;
   typesState.types = typesState.types.filter(each => each !== type);
   renderTypes();
   return;
  }
  if (event.target.closest('[data-types-add]')) addType(typesInput().value);
  const hint = event.target.closest('[data-types-hint]');
  if (hint) addType(hint.dataset.suggest);
  if (event.target.closest('[data-types-default]')) {
   typesForm().elements.namedItem('useDefault').value = 'true';
   typesForm().requestSubmit();
  }
  if (event.target.closest('#module-types-cancel')) dialog.close();
 });
 document.addEventListener('input', event => {
  if (event.target && event.target.id === 'module-types-input') updateHint();
 });
 document.addEventListener('keydown', event => {
  if (event.key === 'Enter' && event.target && event.target.id === 'module-types-input') {
   event.preventDefault();
   addType(event.target.value);
  }
 });
})();

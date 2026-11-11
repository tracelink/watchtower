const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/alert-settings.js'), 'utf8');

const dom = new JSDOM(`<!doctype html><body>
  <button id="addRoute" data-wt-dialog-target="#routeDialog" data-route-add>Add route</button>
  <button id="editRoute" data-wt-dialog-target="#routeDialog" data-route-edit
      data-id="7" data-alert-type="SECRET_DETECTED" data-channel-id="3" data-min-priority="HIGH"
      data-api-label="" data-repo-include="payments-*" data-repo-exclude=""
      data-aggregation="PER_FINDING" data-dedupe="48">Edit</button>
  <md-dialog id="routeDialog">
    <div data-route-dialog-title>Add route</div>
    <form id="routeForm" action="/alertsettings/routes/add">
      <input type="hidden" name="id" data-route-id disabled>
      <md-outlined-select data-route-field="alertType"></md-outlined-select>
      <md-outlined-select data-route-field="channelId"></md-outlined-select>
      <label><input type="radio" name="aggregation" value="PER_SCAN">Per scan</label>
      <label><input type="radio" name="aggregation" value="PER_FINDING">Per finding</label>
      <input type="hidden" name="dedupeWindowHours" data-route-field="dedupeWindowHours">
      <label><input type="radio" name="repeatChoice" value="24">1 day</label>
      <label><input type="radio" name="repeatChoice" value="168">7 days</label>
      <label><input type="radio" name="repeatChoice" value="720">30 days</label>
      <label><input type="radio" name="repeatChoice" value="custom">Custom</label>
      <label data-route-repeat-custom><input type="number" data-route-repeat-hours></label>
      <section data-route-filters>
        <label><input type="radio" name="minPriority" value="">Any</label>
        <label><input type="radio" name="minPriority" value="HIGH">High</label>
        <div data-route-integrations><label><input type="radio" name="apiLabelFilter" value="">All</label></div>
        <md-outlined-text-field data-route-field="repoInclude"></md-outlined-text-field>
        <md-outlined-text-field data-route-field="repoExclude"></md-outlined-text-field>
      </section>
    </form>
    <button id="cancelRouteDialog">Cancel</button>
    <button data-route-submit>Add route</button>
  </md-dialog>

  <button id="addChannel" data-wt-dialog-target="#channelDialog" data-channel-add>Add channel</button>
  <button id="editChannel" data-wt-dialog-target="#channelDialog" data-channel-edit
      data-id="3" data-name="AppSec space" data-enabled="true">Edit</button>
  <button id="editDisabledChannel" data-wt-dialog-target="#channelDialog" data-channel-edit
      data-id="4" data-name="Old space" data-enabled="false">Edit</button>
  <md-dialog id="channelDialog">
    <div data-channel-dialog-title>Add channel</div>
    <form id="channelForm" action="/alertsettings/channels/add">
      <input type="hidden" name="id" data-channel-id disabled>
      <label data-channel-enabled-row hidden><input type="checkbox" name="enabled" value="true"
          data-channel-enabled disabled> Enabled</label>
      <md-outlined-text-field data-channel-name></md-outlined-text-field>
      <md-outlined-text-field data-channel-url></md-outlined-text-field>
    </form>
    <button id="cancelChannelDialog">Cancel</button>
    <button data-channel-submit>Add channel</button>
  </md-dialog>

  <button id="deleteRoute" data-wt-dialog-target="#confirmDeleteDialog"
      data-delete-action="/alertsettings/routes/delete" data-delete-id="7" data-delete-title="Delete route"
      data-delete-label="the route for SECRET_DETECTED to AppSec space">Delete</button>
  <md-dialog id="confirmDeleteDialog">
    <form id="confirmDeleteForm" action="/alertsettings/routes/delete">
      <strong data-delete-name>this item</strong>
      <input type="hidden" name="id" data-delete-id-field>
    </form>
    <span data-delete-title>Delete</span>?
    <button id="cancelConfirmDeleteDialog">Cancel</button>
  </md-dialog>
</body>`, {runScripts: 'dangerously'});

const {document} = dom.window;
const opened = [];
for (const id of ['routeDialog', 'channelDialog', 'confirmDeleteDialog']) {
  const dialog = document.getElementById(id);
  dialog.show = () => opened.push(id);
  dialog.close = () => {};
}
dom.window.eval(script);

const field = (name) => document.querySelector(`[data-route-field="${name}"]`);
const choice = (name) => document.querySelector(`input[name="${name}"]:checked`)?.value;
const routeForm = document.getElementById('routeForm');

// Editing a route fills every field, switches to the update action and opens the filters.
document.getElementById('editRoute').click();
assert.equal(opened.pop(), 'routeDialog');
assert.equal(routeForm.getAttribute('action'), '/alertsettings/routes/update');
assert.equal(document.querySelector('[data-route-id]').value, '7');
assert.equal(document.querySelector('[data-route-id]').disabled, false);
assert.equal(field('alertType').value, 'SECRET_DETECTED');
assert.equal(field('channelId').value, '3');
assert.equal(choice('minPriority'), 'HIGH');
assert.equal(field('repoInclude').value, 'payments-*');
assert.equal(choice('aggregation'), 'PER_FINDING');
assert.equal(field('dedupeWindowHours').value, '48');
assert.equal(choice('repeatChoice'), 'custom');
assert.equal(document.querySelector('[data-route-repeat-custom]').hidden, false);
const week = document.querySelector('input[name="repeatChoice"][value="168"]');
week.checked = true;
week.dispatchEvent(new dom.window.Event('change', {bubbles: true}));
assert.equal(field('dedupeWindowHours').value, '168');
assert.equal(document.querySelector('[data-route-repeat-custom]').hidden, true);
// A filter for a removed integration must survive opening/saving the route.
document.getElementById('editRoute').dataset.apiLabel = 'Retired <integration>';
document.getElementById('editRoute').click();
assert.equal(choice('apiLabelFilter'), 'Retired <integration>');
assert.equal(document.querySelector('[data-route-integrations] integration'), null);
assert.equal(document.querySelector('[data-route-dialog-title]').textContent, 'Edit route');
assert.equal(document.querySelector('[data-route-submit]').textContent, 'Save route');

// Adding afterwards resets to defaults, so no edit values leak into a new route.
document.getElementById('addRoute').click();
assert.equal(routeForm.getAttribute('action'), '/alertsettings/routes/add');
assert.equal(document.querySelector('[data-route-id]').disabled, true);
assert.equal(field('alertType').value, '');
assert.equal(choice('minPriority'), '');
assert.equal(field('repoInclude').value, '');
assert.equal(choice('aggregation'), 'PER_SCAN');
assert.equal(field('dedupeWindowHours').value, '720');
assert.equal(choice('repeatChoice'), '720');
assert.equal(choice('apiLabelFilter'), '');
assert.equal(document.querySelector('[data-route-extra]'), null);
assert.equal(document.querySelector('[data-route-dialog-title]').textContent, 'Add route');

// Editing a channel keeps its state, never pre-fills the URL and makes the URL optional.
const channelForm = document.getElementById('channelForm');
const url = channelForm.querySelector('[data-channel-url]');
document.getElementById('editChannel').click();
assert.equal(channelForm.getAttribute('action'), '/alertsettings/channels/update');
assert.equal(channelForm.querySelector('[data-channel-id]').value, '3');
// Enable/Disable lives in the edit dialog, not as a row button.
const enabled = channelForm.querySelector('[data-channel-enabled]');
assert.equal(enabled.disabled, false);
assert.equal(enabled.checked, true);
assert.equal(channelForm.querySelector('[data-channel-enabled-row]').hidden, false);
assert.equal(channelForm.querySelector('[data-channel-name]').value, 'AppSec space');
assert.equal(url.value, '');
assert.equal(url.required, false);
assert.match(url.getAttribute('supporting-text'), /Leave blank/);

document.getElementById('editDisabledChannel').click();
assert.equal(enabled.checked, false, 'a disabled channel opens unchecked');

document.getElementById('addChannel').click();
assert.equal(channelForm.getAttribute('action'), '/alertsettings/channels/add');
assert.equal(channelForm.querySelector('[data-channel-id]').disabled, true);
assert.equal(enabled.disabled, true);
assert.equal(channelForm.querySelector('[data-channel-enabled-row]').hidden, true,
  'a new channel is always enabled');
assert.equal(channelForm.querySelector('[data-channel-name]').value, '');
assert.equal(url.required, true);

// Delete confirmation targets the clicked item.
document.getElementById('deleteRoute').click();
assert.equal(opened.pop(), 'confirmDeleteDialog');
assert.equal(document.getElementById('confirmDeleteForm').getAttribute('action'),
  '/alertsettings/routes/delete');
assert.equal(document.querySelector('[data-delete-id-field]').value, '7');
assert.equal(document.querySelector('[data-delete-name]').textContent,
  'the route for SECRET_DETECTED to AppSec space');
// The dialog is titled for what is being deleted, not just "Delete".
assert.equal(document.querySelector('#confirmDeleteDialog [data-delete-title]').textContent, 'Delete route');

console.log('Alert settings dialogs jsdom test passed');

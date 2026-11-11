(function() {
  var search = document.querySelector('[data-privilege-search]');
  var status = document.querySelector('[data-privilege-status]');
  var rows = Array.from(document.querySelectorAll('[data-privilege-row]'));
  if (!search || !status) return;

  function update() {
    var query = search.value.trim().toLowerCase();
    var visible = 0;
    rows.forEach(function(row) {
      var matches = !query || (row.dataset.privilegeText || '').toLowerCase().includes(query);
      row.hidden = !matches;
      if (matches) visible += 1;
    });
    document.querySelectorAll('[data-privilege-group]').forEach(function(group) {
      group.hidden = !group.querySelector('[data-privilege-row]:not([hidden])');
    });
    status.textContent = visible + (visible === 1 ? ' privilege shown' : ' privileges shown');
  }

  function checkboxes(group) {
    return Array.from(group.querySelectorAll('md-checkbox, input[type="checkbox"]'))
      .filter(function(checkbox) { return !checkbox.disabled; });
  }

  // One button per group: "Select all" until every privilege in it is granted, then "Clear all".
  function label(button) {
    var boxes = checkboxes(button.closest('[data-privilege-group]'));
    var allChecked = boxes.length > 0 && boxes.every(function(checkbox) { return checkbox.checked; });
    button.textContent = allChecked ? 'Clear all' : 'Select all';
    return allChecked;
  }

  document.querySelectorAll('[data-toggle-group]').forEach(function(button) {
    var group = button.closest('[data-privilege-group]');
    button.addEventListener('click', function() {
      var select = !label(button);
      checkboxes(group).forEach(function(checkbox) { checkbox.checked = select; });
      label(button);
    });
    group.addEventListener('change', function() { label(button); });
    label(button);
  });
  search.addEventListener('input', update);
  update();
})();

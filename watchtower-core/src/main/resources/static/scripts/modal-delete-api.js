(function() {
	// Delete an integration (configuration/deleteintegration.html), from the list or its own page.
	// Each Delete trigger carries the integration's name, provider, repository count and (when it
	// has one repository) that repository's name; the dialog says what deleting does as chips and
	// asks for the name (wt-dialog.js enables Delete once it matches; the server checks it too).
	var dialog = document.getElementById('deleteModal');
	if (!dialog || dialog.dataset.deleteReady) {
		return;
	}
	dialog.dataset.deleteReady = 'true';
	var activeTrigger = null;
	function setText(selector, text) {
		dialog.querySelectorAll(selector).forEach(function(el) {
			el.textContent = text;
		});
	}
	document.querySelectorAll('[data-wt-dialog-target="#deleteModal"]').forEach(function(trigger) {
		trigger.addEventListener('click', function() {
			activeTrigger = trigger;
			var label = trigger.dataset.label || '';
			document.getElementById('modalApiLabel').value = label;
			setText('#deleteApiConfigName', label);
			setText('[data-delete-provider-chip]', trigger.dataset.provider
				? 'Scans stop connecting to ' + trigger.dataset.provider : 'Scans stop connecting');
			// "N repositories use it" and the "Also delete" box only when it has repositories; the
			// box names the repository when there is just one, and starts unticked every time.
			var count = Number(trigger.dataset.repoCount || 0);
			dialog.querySelectorAll('[data-delete-repos]').forEach(function(el) {
				el.hidden = count === 0;
			});
			setText('[data-delete-repo-count]', count === 1 ? '1 repository uses it' : count + ' repositories use it');
			var only = trigger.dataset.repoName;
			setText('[data-delete-repos-label]', count === 1 && only
				? 'Also delete ' + only + ' and its repository scans'
				: 'Also delete its ' + count + ' repositories and their repository scans');
			var also = dialog.querySelector('md-checkbox[name="deleteRepositories"]');
			if (also) {
				also.checked = false;
			}
			var confirmField = dialog.querySelector('[data-wt-confirm-name]');
			if (confirmField) {
				confirmField.setAttribute('data-wt-confirm-name', label);
				confirmField.setAttribute('placeholder', label);
				confirmField.value = '';
				if (window.watchtowerSyncConfirm) {
					window.watchtowerSyncConfirm(confirmField);
				}
			}
			dialog.show();
		});
	});
	var cancelButton = document.getElementById('cancelDeleteModal');
	if (cancelButton) {
		cancelButton.addEventListener('click', function() {
			dialog.close();
		});
	}
	dialog.addEventListener('closed', function() {
		if (activeTrigger) {
			activeTrigger.focus();
			activeTrigger = null;
		}
	});
})();

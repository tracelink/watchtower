// Low-priority success/info notifications dismiss after six seconds. Warning and error
// notifications remain until the user closes them. Hovering or focusing pauses the timer.
var WT_ALERT_AUTO_DISMISS_DELAY_MS = 6000;
var wtAlertTimers = new WeakMap();

function wtStartAlertTimer(alertEl) {
	wtStopAlertTimer(alertEl);
	wtAlertTimers.set(alertEl, setTimeout(function () {
		bootstrap.Alert.getOrCreateInstance(alertEl).close();
	}, WT_ALERT_AUTO_DISMISS_DELAY_MS));
}

function wtStopAlertTimer(alertEl) {
	var timer = wtAlertTimers.get(alertEl);
	if (timer) clearTimeout(timer);
	wtAlertTimers.delete(alertEl);
}

function wtScheduleAlertAutoDismiss() {
	document.querySelectorAll('.alert-dismissible.alert-success, .alert-dismissible.alert-info')
			.forEach(function (alertEl) {
				if (alertEl.dataset.autoDismissReady === 'true') return;
				alertEl.dataset.autoDismissReady = 'true';
				alertEl.addEventListener('mouseenter', function () { wtStopAlertTimer(alertEl); });
				alertEl.addEventListener('mouseleave', function () { wtStartAlertTimer(alertEl); });
				alertEl.addEventListener('focusin', function () { wtStopAlertTimer(alertEl); });
				alertEl.addEventListener('focusout', function (event) {
					if (!alertEl.contains(event.relatedTarget)) wtStartAlertTimer(alertEl);
				});
				wtStartAlertTimer(alertEl);
			});
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', wtScheduleAlertAutoDismiss, {once: true});
} else {
	wtScheduleAlertAutoDismiss();
}
document.addEventListener('htmx:afterSettle', wtScheduleAlertAutoDismiss);

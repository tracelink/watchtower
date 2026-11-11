var toggleChart = (hide, none, canvas, message) => {
	if (!document.getElementById(none) || !document.getElementById(canvas)) return;
	if (hide) {
		document.getElementById(none).textContent = message || 'No data to display.';
		document.getElementById(canvas).style.display = 'none';
	} else {
		document.getElementById(none).textContent = '';
		document.getElementById(canvas).style.display = 'block';
	}
	const region = document.getElementById(none).closest('[data-chart-region]');
	if (region) region.setAttribute('aria-busy', 'false');
};

var wtSetChartLoading = (stateId, message) => {
	const state = document.getElementById(stateId);
	if (!state) return;
	state.textContent = message || 'Loading chart…';
	const region = state.closest('[data-chart-region]');
	if (region) region.setAttribute('aria-busy', 'true');
};

// IMPROVEMENT_PLAN.md item 10.14.
//
// The previous palette was 24 raw rgba() literals faded across six transparency steps down to
// 0.25. Two of those base colours were near-white (255,255,248 and 242,242,242) and so invisible
// on a light background before any fading, and at 0.25 alpha most of the rest were unreadable in
// either theme. These twelve are all mid-tone - nothing near white or near black - so each stays
// legible on both --wt-bg values, and only two alpha steps are used, which still yields 24
// distinct series before wrapping.
var WT_CHART_PALETTE = [
	'79,109,245',   // indigo
	'224,53,91',    // rose
	'22,163,74',    // green
	'217,119,6',    // amber
	'8,145,178',    // cyan
	'147,51,234',   // purple
	'14,165,233',   // sky
	'202,138,4',    // dark yellow
	'5,150,105',    // emerald
	'219,39,119',   // pink
	'124,58,237',   // violet
	'225,29,72'     // crimson
];

var WT_CHART_ALPHAS = [1, 0.72];

var getColors = (numColors) => {
	let graphColors = [];
	let i = 0;
	let j = 0;

	while (graphColors.length < numColors) {
		graphColors.push('rgba(' + WT_CHART_PALETTE[j] + ',' + WT_CHART_ALPHAS[i] + ')');

		if (j === WT_CHART_PALETTE.length - 1) {
			j = 0;
			i += 1;
		} else {
			j += 1;
		}

		if (i === WT_CHART_ALPHAS.length) {
			i = 0;
		}
	}

	return graphColors;
};

// Chart.js 4.x has native theme support via plugins API and CSS color integration.
var wtThemeValue = (name, fallback) => {
	const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
	return value || fallback;
};

var wtApplyChartDefaults = () => {
	if (typeof Chart === 'undefined') {
		return;
	}
	const ink = wtThemeValue('--wt-text-muted', '#616875');
	const grid = wtThemeValue('--wt-border', '#e3e6ef');

	Chart.defaults.color = ink;
	Chart.defaults.font.family = wtThemeValue('--wt-font', 'sans-serif');
	Chart.defaults.plugins.legend.labels.color = ink;
	Chart.defaults.scale.ticks.color = ink;
	Chart.defaults.scale.grid.color = grid;
};

// Chart.js copies the defaults above into each chart's own options at construction time, so
// changing them later does nothing to a chart that already exists - the live instances have to be
// patched individually and redrawn.
var wtRethemeExistingCharts = () => {
	if (typeof Chart === 'undefined') {
		return;
	}
	const ink = wtThemeValue('--wt-text-muted', '#616875');
	const grid = wtThemeValue('--wt-border', '#e3e6ef');

	// Chart.js 4.x stores instances in Chart.instances object (iterate via Object.values)
	Object.values(Chart.instances).forEach((chart) => {
		const options = chart.options || {};

		// Update legend colors (now in plugins.legend)
		if (options.plugins && options.plugins.legend && options.plugins.legend.labels) {
			options.plugins.legend.labels.color = ink;
		}

		// Update scales (now x/y objects instead of xAxes/yAxes arrays)
		if (options.scales) {
			Object.keys(options.scales).forEach((scaleId) => {
				const scale = options.scales[scaleId];
				if (scale.ticks) {
					scale.ticks.color = ink;
				}
				if (scale.title) {
					scale.title.color = ink;
				}
				if (scale.grid) {
					scale.grid.color = grid;
				}
			});
		}
		chart.update();
	});
};

wtApplyChartDefaults();

var wtFetchMetric = async (url) => {
	const response = await fetch(url, {headers: {'Accept': 'application/json'}});
	if (!response.ok) throw new Error(`Metrics request failed (${response.status})`);
	const result = await response.json();
	if (!result || result.error || !Array.isArray(result.labels)) {
		throw new Error(result && result.error ? String(result.error) : 'Invalid metrics response');
	}
	return result;
};

var wtMetricQuery = (selectId, period) => {
	const select = document.getElementById(selectId);
	let range = document.getElementById(selectId + '-custom-range');
	if (period !== 'custom') {
		if (range) range.hidden = true;
		return `period=${encodeURIComponent(period)}`;
	}
	if (!range) {
		const today = new Date();
		const prior = new Date(today);
		prior.setDate(today.getDate() - 29);
		const dateValue = date => {
			const year = date.getFullYear();
			const month = String(date.getMonth() + 1).padStart(2, '0');
			const day = String(date.getDate()).padStart(2, '0');
			return `${year}-${month}-${day}`;
		};
		const fromId = selectId + '-custom-from';
		const toId = selectId + '-custom-to';
		const errorId = selectId + '-custom-error';
		range = document.createElement('fieldset');
		range.id = selectId + '-custom-range';
		range.className = 'wt-custom-date-range mt-2';
		const legend = document.createElement('legend');
		legend.className = 'small mb-1';
		legend.textContent = 'Custom dates (system time)';
		const fromInput = document.createElement('md-outlined-text-field');
		fromInput.id = fromId;
		fromInput.type = 'date';
		fromInput.label = 'From';
		fromInput.value = dateValue(prior);
		fromInput.setAttribute('aria-describedby', errorId);
		const toInput = document.createElement('md-outlined-text-field');
		toInput.id = toId;
		toInput.type = 'date';
		toInput.label = 'To';
		toInput.value = dateValue(today);
		toInput.setAttribute('aria-describedby', errorId);
		const error = document.createElement('div');
		error.id = errorId;
		error.className = 'wt-custom-date-error';
		error.setAttribute('role', 'alert');
		error.hidden = true;
		range.append(legend, fromInput, toInput, error);
		select.parentElement.appendChild(range);
		range.querySelectorAll('md-outlined-text-field').forEach(input => input.addEventListener('change', () =>
			select.dispatchEvent(new Event('change', {bubbles: true}))));
	}
	range.hidden = false;
	const inputs = range.querySelectorAll('md-outlined-text-field');
	const error = range.querySelector('[role="alert"]');
	if (!inputs[0].value || !inputs[1].value || inputs[0].value > inputs[1].value) {
		error.textContent = 'Choose a valid From and To date.';
		error.hidden = false;
		throw new Error('Choose a valid From and To date.');
	}
	error.textContent = '';
	error.hidden = true;
	return `start=${encodeURIComponent(inputs[0].value)}&end=${encodeURIComponent(inputs[1].value)}`;
};

// Guarded because this file re-runs on every htmx-boosted navigation (it lives inside #content),
// while documentElement and the media query list do not - without the flag each visit to a
// dashboard would add another listener.
if (!window.wtChartThemeWatch) {
	window.wtChartThemeWatch = true;
	const onThemeChange = () => {
		wtApplyChartDefaults();
		wtRethemeExistingCharts();
	};
	new MutationObserver(onThemeChange).observe(document.documentElement, {
		attributes: true,
		attributeFilter: ['data-theme']
	});
	window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', onThemeChange);
}

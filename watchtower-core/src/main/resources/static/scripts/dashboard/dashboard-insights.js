// Wrapped: htmx re-runs this file on boosted navigation, so nothing may be declared at top level.
(() => {
const DAILY_BAR_LIMIT = 31;
const TOP_RULES_SHOWN = 6;

/** Opens or closes the Custom range panel (force: true/false), keeping its dates visible. */
const togglePicker = (customButton, force) => {
	const picker = document.querySelector('[data-range-picker]');
	const custom = document.querySelector('[data-dashboard-range-options] [data-period="custom"]');
	if (!picker || !custom) return;
	const open = force === undefined ? picker.hidden : force;
	picker.hidden = !open;
	custom.setAttribute('aria-expanded', String(open));
	const dates = picker.querySelector('fieldset');
	if (open && dates) dates.hidden = false;
};

const isoDate = date => [date.getFullYear(), String(date.getMonth() + 1).padStart(2, '0'),
	String(date.getDate()).padStart(2, '0')].join('-');

/** From and To for a quick range, as local calendar days. */
const quickRange = (key, today) => {
	const day = offset => new Date(today.getFullYear(), today.getMonth(), today.getDate() + offset);
	switch (key) {
		case 'today': return [day(0), day(0)];
		case 'yesterday': return [day(-1), day(-1)];
		case 'this-month': return [new Date(today.getFullYear(), today.getMonth(), 1), day(0)];
		case 'last-month': return [new Date(today.getFullYear(), today.getMonth() - 1, 1),
			new Date(today.getFullYear(), today.getMonth(), 0)];
		case 'this-year': return [new Date(today.getFullYear(), 0, 1), day(0)];
		case '6-months': return [new Date(today.getFullYear(), today.getMonth() - 5, 1), day(0)];
		default: return [day(1 - Number(key)), day(0)];
	}
};

const shortDate = value => {
	const [year, month, day] = String(value).split('-').map(Number);
	return new Date(year, month - 1, day).toLocaleDateString(undefined, {day: '2-digit', month: 'short'});
};

const wirePicker = (select, press) => {
	const picker = document.querySelector('[data-range-picker]');
	if (!picker) return;
	const from = picker.querySelector('[id$="-custom-from"]');
	const to = picker.querySelector('[id$="-custom-to"]');
	const error = picker.querySelector('[role="alert"]');
	const quick = picker.querySelectorAll('[data-quick]');
	const mark = button => quick.forEach(other => other.setAttribute('aria-pressed', String(other === button)));
	if (from && to && !from.value) {
		const [start, end] = quickRange('30', new Date());
		from.value = isoDate(start);
		to.value = isoDate(end);
	}
	quick.forEach(button => button.addEventListener('click', () => {
		const [start, end] = quickRange(button.dataset.quick, new Date());
		from.value = isoDate(start);
		to.value = isoDate(end);
		mark(button);
	}));
	[from, to].forEach(input => input && input.addEventListener('input', () => mark(null)));
	const cancel = picker.querySelector('[data-range-cancel]');
	if (cancel) cancel.addEventListener('click', () => togglePicker(null, false));
	const apply = picker.querySelector('[data-range-apply]');
	if (apply) apply.addEventListener('click', () => {
		if (!from.value || !to.value || from.value > to.value) {
			error.textContent = 'Choose a From date on or before the To date.';
			error.hidden = false;
			return;
		}
		error.textContent = '';
		error.hidden = true;
		const custom = document.querySelector('[data-dashboard-range-options] [data-period="custom"]');
		press(custom);
		const label = custom && custom.querySelector('[data-custom-label]');
		if (label) label.textContent = shortDate(from.value) + ' – ' + shortDate(to.value);
		togglePicker(null, false);
		select.value = 'custom';
		select.dispatchEvent(new Event('change', {bubbles: true}));
	});
	picker.addEventListener('keydown', event => {
		if (event.key === 'Escape') togglePicker(null, false);
	});
};

const formatCount = value => Number(value || 0).toLocaleString();

/** "13 total · busiest 25 Sep (3)" - the takeaway, so nobody has to read the axis. */
const scanSummary = (total, counts, labels) => {
	if (!total) return '0 total';
	const busiest = counts.reduce((best, count, index) => (count > counts[best] ? index : best), 0);
	return formatCount(total) + ' total · busiest ' + labels[busiest] + ' (' + formatCount(counts[busiest]) + ')';
};

/** All time spans years: keep from the first to the last bucket with scans, and name the quiet tail. */
const activeSpan = result => {
	const counts = (result.counts || []).map(count => Number(count || 0));
	const first = counts.findIndex(count => count > 0);
	if (first < 0) return null;
	let last = counts.length - 1;
	while (last > first && counts[last] === 0) last--;
	const labels = result.labels || [];
	const hasYear = label => /\d{4}/.test(String(label));
	let quietSince = null;
	if (last < counts.length - 1) {
		const label = String(labels[last] || '');
		const nextWithYear = labels.slice(last + 1).find(hasYear);
		quietSince = hasYear(label) || !nextWithYear ? label : label + ' ' + String(nextWithYear).match(/\d{4}/)[0];
	}
	return {first, last, quietSince};
};

const sliceTrend = (result, span) => {
	const all = result.labels || [];
	const labels = all.slice(span.first, span.last + 1);
	// Month labels carry the year only at year ends; give the first shown month its year.
	const nextWithYear = all.slice(span.first).find(label => /\d{4}/.test(String(label)));
	if (labels.length && !/\d{4}/.test(String(labels[0])) && nextWithYear) {
		labels[0] = labels[0] + ' ' + String(nextWithYear).match(/\d{4}/)[0];
	}
	return {...result, labels, counts: (result.counts || []).slice(span.first, span.last + 1)};
};

/** "1 scan with an impossible date left out": the server drops pre-2015 days from All time. */
const renderImpossibleDates = result => {
	const chip = document.querySelector('[data-dashboard-impossible-dates]');
	if (!chip) return;
	const count = Number((result && result.impossibleDates) || 0);
	chip.hidden = count === 0;
	if (!count) return;
	const label = chip.querySelector('[data-dashboard-impossible-label]');
	const text = formatCount(count) + (count === 1 ? ' scan' : ' scans') + ' with an impossible date left out';
	if (label) label.textContent = text;
	chip.dataset.tip = (count === 1 ? 'A scan is' : count + ' scans are') + ' dated before '
		+ String(result.impossibleBefore || '2015').slice(0, 4)
		+ '. It is ignored on the chart so the axis starts at the first real month.';
	chip.setAttribute('aria-label', text + '. ' + chip.dataset.tip);
};

const appendTotal = (key, text) => {
	const target = document.querySelector(`[data-dashboard-total="${key}"]`);
	if (target && target.textContent) target.textContent += text;
};

const scannerLabel = name => {
	const simple = String(name || 'Scanner').replace(/Scanner$/, '');
	return simple === 'EsLint' ? 'ESLint' : simple;
};

const distributionRow = (row, total, top, extra) => {
	const percent = total ? Math.round((row.count / total) * 100) : 0;
	const item = document.createElement('li');
	const heading = document.createElement('div');
	const tile = document.createElement('span');
	const name = document.createElement('strong');
	const value = document.createElement('span');
	const track = document.createElement('span');
	const bar = document.createElement('span');
	// Unknown scanners keep a grey "?" tile; the hover says why instead of guessing a scanner.
	tile.className = 'wt-scanner-tile wt-distribution-scanner' + (row.scanner ? ' wt-scanner-tile--ran' : '');
	const icon = document.createElement('span');
	icon.className = 'material-icons';
	icon.setAttribute('aria-hidden', 'true');
	icon.textContent = row.scanner ? row.scanner.icon : 'help';
	tile.append(icon);
	tile.setAttribute('role', 'img');
	tile.tabIndex = 0;
	tile.dataset.tip = row.scanner ? row.scanner.name + ' rule'
		: row.label + ' · scanner unknown (its module isn\'t installed)';
	tile.setAttribute('aria-label', tile.dataset.tip);
	name.textContent = row.label;
	value.textContent = formatCount(row.count) + ' · ' + percent + '%';
	heading.append(tile, name, value);
	track.className = 'wt-distribution-track';
	bar.dataset.distributionBar = '';
	bar.className = 'wt-distribution-bar';
	// Bars are relative to the top rule, so the first is full width and the rest compare to it.
	bar.style.setProperty('--wt-bar-size', (top ? Math.round((row.count / top) * 100) : 0) + '%');
	track.append(bar);
	item.append(heading, track);
	if (extra) {
		item.hidden = true;
		item.dataset.dashboardExtraRule = '';
	}
	return item;
};

window.WatchtowerDashboardInsights = class WatchtowerDashboardInsights {
	constructor(selectId, scanType) {
		this.selectId = selectId;
		this.scanType = scanType;
		this.charts = {};
		this.requestSequence = 0;
	}

	prefersReducedMotion() {
		return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
	}

	/** 7 and 30 days (and short custom ranges) are read day by day as bars; longer ranges as a trend line. */
	isDaily(labels) {
		if (this.period === 'last-week' || this.period === 'last-thirty-days') return true;
		return this.period === 'custom' && (labels || []).length <= DAILY_BAR_LIMIT;
	}

	renderTrend(canvasId, stateId, label, result) {
		const counts = (result.counts || []).map(count => Number(count || 0));
		const labels = result.labels || [];
		const total = counts.reduce((sum, count) => sum + count, 0);
		const isScans = label.startsWith('Scans');
		const totalTarget = document.querySelector(
			`[data-dashboard-total="${isScans ? 'scans' : 'findings'}"]`);
		if (totalTarget) totalTarget.textContent = isScans ? scanSummary(total, counts, labels) : formatCount(total) + ' total';
		const hasData = counts.some(count => count !== 0);
		toggleChart(!hasData, stateId, canvasId);
		if (this.charts[canvasId]) this.charts[canvasId].destroy();
		if (!hasData) return null;

		const color = isScans
			? wtThemeValue('--wt-accent', '#4f6df5')
			: wtThemeValue('--wt-chart-findings', '#f97316');
		const daily = this.isDaily(labels);
		const context = document.getElementById(canvasId).getContext('2d');
		this.charts[canvasId] = new Chart(context, {
			type: daily ? 'bar' : 'line',
			data: {
				labels: labels,
				datasets: [{
					label: label,
					data: counts,
					borderColor: color,
					backgroundColor: color,
					borderWidth: daily ? 0 : 2,
					borderRadius: daily ? 3 : 0,
					maxBarThickness: 18,
					pointRadius: daily ? 0 : 3,
					pointHoverRadius: 5,
					tension: 0,
					fill: false
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				animation: this.prefersReducedMotion() ? false : {duration: 180},
				plugins: {legend: {display: false}, tooltip: {mode: 'index', intersect: false}},
				scales: {
					x: {grid: {display: false}, ticks: {maxTicksLimit: 7}},
					y: {beginAtZero: true, ticks: {precision: 0}}
				}
			}
		});
		return this.charts[canvasId];
	}

	/** With no scans in the chosen range, the charts become one line with a way to widen it. */
	renderEmptyRange(scans) {
		const empty = document.querySelector('[data-dashboard-empty]');
		const charts = document.querySelector('[data-dashboard-charts]');
		if (!empty || !charts) return;
		const total = (scans.counts || []).reduce((sum, count) => sum + Number(count || 0), 0);
		const isEmpty = total === 0 && this.period !== 'all-time';
		empty.hidden = !isEmpty;
		charts.hidden = isEmpty;
		const lastScan = document.querySelector('.wt-recent-scans td.localizetime');
		const lastText = empty.querySelector('[data-dashboard-last-scan]');
		if (lastText) lastText.textContent = lastScan && lastScan.textContent.trim()
			? 'Last scan finished ' + lastScan.textContent.trim() + '.' : '';
		const widen = empty.querySelector('[data-dashboard-show-all-time]');
		const allTime = document.querySelector('[data-dashboard-range-options] [data-period="all-time"]');
		if (widen) widen.onclick = () => allTime && allTime.click();
	}

	/** Adds "avg N per scan" to the findings total once both trends are known. */
	renderAverage(scans, findings) {
		const target = document.querySelector('[data-dashboard-total="findings"]');
		const scanTotal = (scans.counts || []).reduce((sum, count) => sum + Number(count || 0), 0);
		const findingTotal = (findings.counts || []).reduce((sum, count) => sum + Number(count || 0), 0);
		if (!target || !scanTotal) return;
		target.textContent = formatCount(findingTotal) + ' total · avg '
			+ (findingTotal / scanTotal).toFixed(1).replace(/\.0$/, '') + ' per scan';
	}

	renderPerformanceTrend(result) {
		const canvasId = 'performance-trend';
		const stateId = 'performance-no-data';
		if (!document.getElementById(canvasId)) return null;
		const samples = (result.samples || []).map(value => Number(value || 0));
		const totalSamples = samples.reduce((sum, value) => sum + value, 0);
		const totalTarget = document.querySelector('[data-dashboard-total="performance"]');
		if (totalTarget) {
			totalTarget.textContent = totalSamples
				? totalSamples + (totalSamples === 1 ? ' scan averaged' : ' scans averaged')
				: 'No samples';
		}
		toggleChart(totalSamples === 0, stateId, canvasId);
		if (this.charts[canvasId]) this.charts[canvasId].destroy();
		if (!totalSamples) return null;
		// One stacked bar per day: each step's share of the average scan; the total is in the tooltip.
		const scannerSeries = result.scannerSeries || [];
		const steps = [
			['Source', result.sourceMs, wtThemeValue('--wt-info-strong', '#2563a8')],
			['Processing', result.processingMs, wtThemeValue('--wt-warning-strong', '#9a6700')]
		];
		if (!scannerSeries.length) {
			steps.push(['Scanners', result.scannersMs, wtThemeValue('--wt-success-strong', '#168a50')]);
		}
		const scannerColors = getColors(scannerSeries.length);
		scannerSeries.forEach((scanner, index) => steps.push(
			[scannerLabel(scanner.name), scanner.values, scannerColors[index]]));
		const totals = (result.totalMs || []).map(value => Number(value || 0) / 1000);
		// Daily ranges stack each step in one bar per day; trend ranges draw one line per step
		// and a dashed total (UAT walkthrough, 2026-10-16).
		const daily = this.isDaily(result.labels);
		const datasets = steps.map(([label, values, color]) => (daily ? {
			label: label,
			data: (values || []).map(value => Number(value || 0) / 1000),
			backgroundColor: color,
			borderWidth: 0,
			maxBarThickness: 22,
			stack: 'scan'
		} : {
			label: label,
			data: (values || []).map(value => Number(value || 0) / 1000),
			borderColor: color,
			backgroundColor: color,
			borderWidth: 2,
			pointRadius: 2,
			pointHoverRadius: 4,
			tension: 0,
			fill: false
		}));
		if (!daily) {
			const total = wtThemeValue('--wt-text', '#1a1f36');
			datasets.push({label: 'Total', data: totals, borderColor: total, backgroundColor: total,
				borderWidth: 2, borderDash: [5, 4], pointRadius: 2, pointHoverRadius: 4, tension: 0, fill: false});
		}
		const context = document.getElementById(canvasId).getContext('2d');
		this.charts[canvasId] = new Chart(context, {
			type: daily ? 'bar' : 'line',
			data: {
				labels: result.labels || [],
				datasets: datasets
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				animation: this.prefersReducedMotion() ? false : {duration: 180},
				interaction: {mode: 'index', intersect: false},
				plugins: {
					legend: {display: true, position: 'bottom', labels: {boxWidth: 10, boxHeight: 10}},
					tooltip: {callbacks: {
						label: context => context.dataset.label + ': ' + context.parsed.y.toFixed(1) + ' s',
						footer: items => items.length
							? 'Average scan: ' + (totals[items[0].dataIndex] || 0).toFixed(1) + ' s' : ''
					}}
				},
				scales: {
					x: {stacked: daily, grid: {display: false}, ticks: {maxTicksLimit: 7}},
					y: {stacked: daily, beginAtZero: true, title: {display: true, text: 'Seconds'}}
				}
			}
		});
		return this.charts[canvasId];
	}

	/** Repository scans already store elapsed local scan time, but have no PR phase breakdown. */
	renderDurationTrend(result) {
		const canvasId = 'performance-trend';
		const stateId = 'performance-no-data';
		if (!document.getElementById(canvasId)) return null;
		const samples = (result.samples || []).map(value => Number(value || 0));
		const totalSamples = samples.reduce((sum, value) => sum + value, 0);
		const totalTarget = document.querySelector('[data-dashboard-total="performance"]');
		if (totalTarget) totalTarget.textContent = totalSamples
			? totalSamples + (totalSamples === 1 ? ' scan averaged' : ' scans averaged') : 'No samples';
		toggleChart(totalSamples === 0, stateId, canvasId);
		if (this.charts[canvasId]) this.charts[canvasId].destroy();
		if (!totalSamples) return null;
		const daily = this.isDaily(result.labels);
		const color = wtThemeValue('--wt-info-strong', '#2563a8');
		const context = document.getElementById(canvasId).getContext('2d');
		this.charts[canvasId] = new Chart(context, {
			type: daily ? 'bar' : 'line',
			data: {
				labels: result.labels || [],
				datasets: [{
					label: 'Average repository scan',
					data: (result.totalMs || []).map(value => Number(value || 0) / 1000),
					borderColor: color,
					backgroundColor: color,
					borderWidth: daily ? 0 : 2,
					maxBarThickness: 22,
					pointRadius: daily ? 0 : 3,
					pointHoverRadius: 5,
					tension: 0,
					fill: false
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				animation: this.prefersReducedMotion() ? false : {duration: 180},
				plugins: {legend: {display: false}, tooltip: {callbacks: {
					label: item => 'Average repository scan: ' + item.parsed.y.toFixed(1) + ' s'
				}}},
				scales: {
					x: {grid: {display: false}, ticks: {maxTicksLimit: 7}},
					y: {beginAtZero: true, title: {display: true, text: 'Seconds'}}
				}
			}
		});
		return this.charts[canvasId];
	}

	renderDistribution(result) {
		const list = document.querySelector('[data-dashboard-distribution]');
		const state = document.getElementById('distribution-no-data');
		if (!list || !state) return;
		list.replaceChildren();
		const names = result.names || result.labels || [];
		const rows = (result.labels || []).map((label, index) => ({
			label: names[index] || label,
			scanner: (result.scanners || [])[index] || null,
			count: Number((result.counts || [])[index] || 0)
		})).filter(row => row.count > 0).sort((a, b) => b.count - a.count);
		const total = rows.reduce((sum, row) => sum + row.count, 0);
		const top = rows.length ? rows[0].count : 0;
		const rankedTotal = document.querySelector('[data-dashboard-ranked-total]');
		if (rankedTotal) rankedTotal.textContent = formatCount(total) + ' findings';
		state.textContent = rows.length ? '' : 'No findings in this range.';
		rows.forEach((row, index) => list.append(distributionRow(row, total, top, index >= TOP_RULES_SHOWN)));
		this.syncShowAll(list, rows.length);
	}

	/** Shows the first rules and an "All N rules" button instead of a scrolling box. */
	syncShowAll(list, count) {
		const button = document.querySelector('[data-dashboard-show-all]');
		if (!button) return;
		const label = button.querySelector('[data-dashboard-show-all-label]');
		const icon = button.querySelector('.material-icons');
		button.hidden = count <= TOP_RULES_SHOWN;
		const apply = expanded => {
			button.setAttribute('aria-expanded', String(expanded));
			if (label) label.textContent = expanded ? 'Show top ' + TOP_RULES_SHOWN : 'All ' + count + ' rules';
			if (icon) icon.textContent = expanded ? 'expand_less' : 'expand_more';
			list.querySelectorAll('[data-dashboard-extra-rule]').forEach(item => { item.hidden = !expanded; });
		};
		apply(false);
		button.onclick = () => apply(button.getAttribute('aria-expanded') !== 'true');
	}

	async refresh() {
		const select = document.getElementById(this.selectId);
		const period = select.value || 'all-time';
		this.period = period;
		const sequence = ++this.requestSequence;
		wtSetChartLoading('scans-no-data', 'Loading scan trend…');
		wtSetChartLoading('findings-no-data', 'Loading finding trend…');
		const performanceEnabled = Boolean(document.getElementById('performance-trend'));
		if (performanceEnabled) {
			wtSetChartLoading('performance-no-data', 'Loading performance trend…');
		}
		const distributionState = document.getElementById('distribution-no-data');
		if (distributionState) distributionState.textContent = 'Loading finding distribution…';
		try {
			const query = wtMetricQuery(this.selectId, period);
			const requests = [
				wtFetchMetric(`/rest/metrics/scans-by-period?${query}&type=${this.scanType}`),
				wtFetchMetric(`/rest/metrics/violations-by-period?${query}&type=${this.scanType}`),
				wtFetchMetric(`/rest/metrics/violations-by-type?${query}&type=${this.scanType}`)
			];
			if (performanceEnabled) {
				requests.push(wtFetchMetric(this.scanType === 'repository'
					? `/rest/metrics/scan-duration-by-period?${query}&type=${this.scanType}`
					: `/rest/metrics/pr-performance-by-period?${query}`));
			}
			const [rawScans, rawFindings, distribution, performance] = await Promise.all(requests);
			if (sequence !== this.requestSequence) return;
			const span = period === 'all-time' ? activeSpan(rawScans) : null;
			const scans = span ? sliceTrend(rawScans, span) : rawScans;
			const findings = span ? sliceTrend(rawFindings, span) : rawFindings;
			this.renderTrend('scans-trend', 'scans-no-data', 'Scans completed', scans);
			renderImpossibleDates(rawScans);
			this.renderTrend('findings-trend', 'findings-no-data', 'Findings found', findings);
			if (span && span.quietSince) appendTotal('scans', ' · none since ' + span.quietSince);
			this.renderAverage(scans, findings);
			this.renderEmptyRange(scans);
			this.renderDistribution(distribution);
			if (performanceEnabled) {
				if (this.scanType === 'repository') this.renderDurationTrend(performance);
				else this.renderPerformanceTrend(performance);
			}
		} catch (error) {
			if (sequence !== this.requestSequence) return;
			toggleChart(true, 'scans-no-data', 'scans-trend', error.message);
			toggleChart(true, 'findings-no-data', 'findings-trend', error.message);
			if (performanceEnabled) {
				toggleChart(true, 'performance-no-data', 'performance-trend', error.message);
			}
			if (distributionState) distributionState.textContent = error.message;
		}
	}

	initialize() {
		const select = document.getElementById(this.selectId);
		if (!select) return;
		select.addEventListener('change', () => this.refresh());
		const options = () => document.querySelectorAll('[data-dashboard-range-options] [data-period]');
		const press = button => options().forEach(other => other.setAttribute('aria-pressed', String(other === button)));
		options().forEach(button => button.addEventListener('click', () => {
			if (button.dataset.period === 'custom') {
				togglePicker(button);
				return;
			}
			togglePicker(button, false);
			press(button);
			const label = document.querySelector('[data-custom-label]');
			if (label) label.textContent = 'Custom';
			select.value = button.dataset.period;
			select.dispatchEvent(new Event('change', {bubbles: true}));
		}));
		wirePicker(select, press);
		this.refresh();
	}
};
})();

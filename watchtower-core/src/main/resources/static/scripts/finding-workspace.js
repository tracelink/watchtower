// Progressive enhancement for the server-rendered report workspace. Filters only the findings
// already loaded in this one report; result-list pagination remains entirely server-side.
(function () {
	'use strict';
	var PAGE_SIZE = 10;

	function normalized(value) {
		return String(value || '').toLocaleLowerCase().trim();
	}

	function initialize(workspace) {
		if (workspace.dataset.initialized === 'true') {
			return;
		}
		workspace.dataset.initialized = 'true';

		var items = Array.from(workspace.querySelectorAll('[data-finding-item]'));
		if (!items.length) {
			return;
		}

		var search = workspace.querySelector('[data-finding-search]');
		var severity = workspace.querySelector('[data-finding-severity]');
		// Severity chips (one per severity in the report) toggle each severity on and off. The
		// visible ones are kept comma-separated in that same filter value; empty means all and
		// "-" means none, so a single value such as reviewSeverity=1 still works.
		var severityChips = Array.from(workspace.querySelectorAll('[data-severity-chip]'));
		var allSeverities = severityChips.map(function (chip) { return chip.dataset.severityChip; });
		function shownSeverities() { return !severity.value ? null : severity.value === '-' ? [] : severity.value.split(','); }
		var location = workspace.querySelector('[data-finding-location]');
		var status = workspace.querySelector('[data-finding-status]');
		var total = workspace.querySelector('[data-finding-total]');
		var empty = workspace.querySelector('[data-finding-empty]');
		var range = workspace.querySelector('[data-finding-range]');
		var previous = workspace.querySelector('[data-finding-previous]');
		var next = workspace.querySelector('[data-finding-next]');
		var listViewport = workspace.querySelector('[data-finding-list-viewport]');
		var detailTitle = workspace.querySelector('[data-detail-title]');
		var detailLocation = workspace.querySelector('[data-detail-location]');
		var detailGuidance = workspace.querySelector('[data-detail-guidance]');
		var detailScore = workspace.querySelector('[data-detail-score]');
		var detailCvss = workspace.querySelector('[data-detail-cvss]');
		var detailVector = workspace.querySelector('[data-detail-vector]');
		var detailVectorRow = workspace.querySelector('[data-detail-vector-row]');
		var detailUrl = workspace.querySelector('[data-detail-url]');
		var detailSource = workspace.querySelector('[data-detail-source]');
		var detailVerify = workspace.querySelector('[data-detail-verify]');
		var detailAction = workspace.querySelector('[data-detail-action]');
		var detailSeverity = workspace.querySelector('.wt-finding-detail-heading .wt-sev');
		var detailPanel = workspace.querySelector('.wt-finding-detail');
		var copyStatus = workspace.querySelector('[data-copy-status]');
		var copyButtons = Array.from(workspace.querySelectorAll('[data-copy-finding]'));
		var filteredItems = items.slice();
		// Scanner filter (reports with an AWS assessment): "", "aws" or "other".
		var scannerMenu = workspace.querySelector('[data-finding-scanner-menu]');
		var scanner = workspace.querySelector('[data-finding-scanner]');
		var scannerEmpty = workspace.querySelector('[data-finding-scanner-empty]');
		var grid = workspace.querySelector('[data-split-workspace]');
		var SCANNER_LABELS = {'': 'All scanners', aws: 'AWS Security Agent', other: 'Other scanners'};
		function scannerCount(group) {
			return items.filter(function (item) { return !group || item.dataset.scannerGroup === group; }).length;
		}
		if (scannerMenu && scanner) {
			scannerMenu.querySelector('[data-finding-scanner-options]').addEventListener('click', function (event) {
				var option = event.target.closest('.wt-menu-item');
				if (!option) return;
				scanner.value = option.value;
				scannerMenu.open = false;
				scannerMenu.querySelector('[data-finding-scanner-label]').textContent = SCANNER_LABELS[option.value] || 'All scanners';
				scannerMenu.querySelectorAll('.wt-menu-item').forEach(function (candidate) {
					candidate.setAttribute('aria-checked', String(candidate === option));
				});
				filter();
			});
		}
		// A scanner group with no findings at all shows the usual "No findings" state, not "No matches".
		function showScannerEmpty() {
			var none = Boolean(scanner && scanner.value && scannerCount(scanner.value) === 0);
			if (scannerEmpty) {
				scannerEmpty.hidden = !none;
				var text = scannerEmpty.querySelector('[data-finding-scanner-empty-text]');
				if (text) text.textContent = scanner && scanner.value === 'aws' ? 'AWS Security Agent reported nothing in this scan.'
					: 'The other scanners reported nothing in this scan.';
			}
			if (grid) grid.hidden = none;
		}
		var currentPage = 0;

		// The file filter is either a chip menu ("All files 3 ▾", data-finding-location-menu)
		// over a hidden value, or a select (older markup and tests).
		var locationMenu = workspace.querySelector('[data-finding-location-menu]');
		var locationValues = Array.from(new Set(items.map(function (item) { return item.dataset.location; })))
			.filter(function (value) { return value; })
			.sort(function (a, b) { return a.localeCompare(b); });
		function showLocationChoice() {
			if (!locationMenu) return;
			var label = locationMenu.querySelector('[data-finding-location-label]');
			label.textContent = location.value || locationMenu.dataset.allLabel || 'All files';
			label.title = location.value || '';
			locationMenu.querySelectorAll('.wt-menu-item').forEach(function (option) {
				option.setAttribute('aria-checked', String(option.value === location.value));
			});
		}
		if (locationMenu) {
			var locationOptions = locationMenu.querySelector('[data-finding-location-options]');
			locationValues.forEach(function (value) {
				var option = document.createElement('button');
				option.type = 'button';
				option.className = 'wt-menu-item wt-menu-item--path';
				option.setAttribute('role', 'menuitemradio');
				option.setAttribute('aria-checked', 'false');
				option.value = value;
				option.textContent = value;
				locationOptions.appendChild(option);
			});
			locationMenu.querySelector('[data-finding-location-count]').textContent = String(locationValues.length);
			locationOptions.addEventListener('click', function (event) {
				var option = event.target.closest('.wt-menu-item');
				if (!option) return;
				location.value = option.value;
				locationMenu.open = false;
				showLocationChoice();
				filter();
			});
		}
		locationValues
			.forEach(function (value) {
				if (locationMenu) return;
				var materialSelect = location.tagName.toLocaleLowerCase() === 'md-outlined-select';
				var option = document.createElement(materialSelect ? 'md-select-option' : 'option');
				option.value = value;
				if (materialSelect) {
					var headline = document.createElement('div');
					headline.slot = 'headline';
					headline.textContent = value;
					option.appendChild(headline);
				} else {
					option.textContent = value;
				}
				location.appendChild(option);
			});

		// Live secret verification, for findings a verifier supports (data-verify-id is absent
		// otherwise): a status chip in the heading and a "Verify live" button in the action row.
		// Set as textContent only, since labels come from the server.
		function showVerification(item) {
			if (!detailVerify) {
				return;
			}
			var id = item.dataset.verifyId || '';
			var form = workspace.querySelector('[data-detail-verify-form]');
			detailVerify.hidden = !id;
			if (form) {
				form.hidden = !id || item.dataset.verifyCanRequest !== 'true';
				form.querySelector('[data-detail-verify-id]').value = id;
			}
			if (!id) {
				return;
			}
			var status = detailVerify.querySelector('[data-detail-verify-status]');
			status.textContent = item.dataset.verifyLabel || 'Not verified yet';
			status.dataset.status = item.dataset.verifyStatus || '';
			detailVerify.querySelector('[data-detail-verify-description]').textContent =
				item.dataset.verifyDescription || '';
		}

		// A module's action on the finding (e.g. "Allowlist…"). Only same-site paths are followed,
		// even though the server already checks them.
		function showAction(item) {
			if (!detailAction) {
				return;
			}
			var url = item.dataset.actionUrl || '';
			var safe = url.charAt(0) === '/' && url.charAt(1) !== '/' && url.charAt(1) !== '\\';
			detailAction.hidden = !safe;
			if (!safe) {
				return;
			}
			detailAction.setAttribute('href', url);
			detailAction.querySelector('[data-detail-action-label]').textContent =
				item.dataset.actionLabel || '';
		}

		// AWS Security Agent findings (AwsReport board, 2026-10-22): the detail adds one chip row
		// (scanner, confidence, validation), a chip per location that shows the code around it at the
		// scanned commit (fetched when opened, never stored, secret lines masked by the server), and a
		// Technical details fold with the AWS ids. Every value is set as text, never as markup.
		function element(tag, className, text) {
			var node = document.createElement(tag);
			if (className) node.className = className;
			if (text !== undefined && text !== null) node.textContent = text;
			return node;
		}
		function icon(name) {
			var node = element('span', 'material-icons', name);
			node.setAttribute('aria-hidden', 'true');
			return node;
		}
		function chip(iconName, text, tip, tone) {
			var node = element('span', 'wt-mini-chip wt-meta-chip' + (tone ? ' wt-tone-' + tone : ''));
			node.tabIndex = 0;
			node.dataset.tip = tip;
			node.appendChild(icon(iconName));
			node.appendChild(element('span', '', text));
			return node;
		}
		function words(code) {
			var text = String(code || '').replace(/[_-]+/g, ' ').trim().toLocaleLowerCase();
			return text ? text.charAt(0).toLocaleUpperCase() + text.slice(1) : '';
		}
		function validationChip(status) {
			var code = String(status || '').toUpperCase();
			if (code === 'VALIDATED' || code === 'CONFIRMED' || code === 'TRUE_POSITIVE') {
				return chip('verified', 'Validated by AWS', 'AWS confirmed this finding by testing it.', 'success');
			}
			if (!code || code === 'UNKNOWN' || code.indexOf('NOT') === 0 || code === 'UNVALIDATED') {
				return chip('help_outline', 'Not validated', 'AWS did not confirm this finding by testing it.');
			}
			return chip('help_outline', words(code), 'AWS validation state: ' + words(code) + '.');
		}
		function copyChip(label, value) {
			var row = element('span', 'wt-provider-id');
			row.appendChild(element('span', '', label + ' '));
			var button = element('button', 'wt-mini-chip wt-meta-chip wt-copy-chip');
			button.type = 'button';
			button.dataset.copyText = value;
			button.dataset.tip = value + '. Click to copy.';
			button.setAttribute('aria-label', 'Copy ' + label + ' ' + value);
			button.appendChild(element('span', 'wt-mono', value));
			button.appendChild(icon('content_copy'));
			row.appendChild(button);
			return row;
		}
		function shortLocation(location) {
			var name = location.file.split('/').pop();
			return name + ':' + location.startLine + (location.endLine > location.startLine ? '–' + location.endLine : '');
		}
		function sourceError(status) {
			return status === 403 ? 'Code can’t be shown for this file: a local scan of it is incomplete, or it is excluded.' :
				status === 409 ? 'The file no longer matches the scanned commit.' :
				status === 503 ? 'Scanned code is temporarily unavailable from the code host. Pick the location again to retry.' :
				'Code unavailable.';
		}
		function renderSource(panel, source) {
			panel.replaceChildren();
			var head = element('div', 'wt-provider-source-head');
			head.appendChild(icon('description'));
			head.appendChild(element('span', 'wt-mono', source.file));
			head.appendChild(element('span', 'wt-text-muted', 'at commit ' + String(source.commit || '').slice(0, 7)));
			head.appendChild(element('span', 'wt-provider-source-spacer'));
			head.appendChild(chip('cloud_off', 'Not stored', 'Read from the repository at the scanned commit when you open it, the same as pull request scans. Watchtower never saves the code.', 'success'));
			// Only when a secrets scanner ran on this scan: otherwise no line was checked, and "masked" would overstate it.
			if (source.secretsScanned) head.appendChild(chip('key_off', 'Secrets masked', 'Any line a secrets scanner flagged is masked, in every report.'));
			panel.appendChild(head);
			var masked = source.maskedLines || [];
			var block = element('div', 'wt-code-block');
			(source.lines || []).forEach(function (text, i) {
				var number = source.startLine + i;
				var flagged = number >= (source.flaggedStartLine || source.startLine) && number <= source.requestedEndLine;
				var row = element('div', 'wt-code-line' + (flagged ? ' wt-code-line-violation' : '') +
					(masked.indexOf(number) >= 0 ? ' wt-code-line-masked' : ''));
				row.appendChild(element('span', 'wt-code-lineno', String(number)));
				row.appendChild(element('span', 'wt-code-text', text));
				block.appendChild(row);
			});
			panel.appendChild(block);
			if (source.truncated) panel.appendChild(element('p', 'wt-field-help', 'Showing the first 80 lines of this location.'));
		}
		function renderLocations(item, detail, container) {
			var locations = detail.locations || [];
			if (!locations.length) return;
			container.appendChild(element('h4', 'wt-meta-label', 'Locations · View source'));
			var row = element('div', 'wt-meta-chips wt-provider-locations');
			var panel = element('div', 'wt-provider-source');
			panel.hidden = true;
			var allowed = detail.sensitive ? [] : (detail.sourceLocations || []);
			// The server says why code is hidden (secret finding, source switched off, or no match).
			var lockedReason = detail.sensitivityReason && allowed.length === 0 && /[.]$/.test(detail.sensitivityReason) ?
				detail.sensitivityReason : 'Code can’t be shown for this location.';
			var buttons = [];
			function open(index) {
				buttons.forEach(function (button, i) { button.setAttribute('aria-pressed', String(i === index)); });
				panel.hidden = false;
				if (allowed.indexOf(index) < 0) {
					panel.replaceChildren(element('p', 'wt-code-unavailable', lockedReason));
					return;
				}
				panel.replaceChildren(element('p', 'wt-code-unavailable', 'Loading code…'));
				var url = new URL(item.dataset.providerDetailUrl, window.location.origin);
				url.pathname += '/source';
				url.searchParams.set('location', String(index));
				fetch(url, {credentials: 'same-origin', cache: 'no-store'}).then(function (response) {
					if (!response.ok) throw new Error(sourceError(response.status));
					return response.json();
				}).then(function (source) {
					if (buttons[index].getAttribute('aria-pressed') === 'true') renderSource(panel, source);
				}).catch(function (error) {
					panel.replaceChildren(element('p', 'wt-code-unavailable', error.message || 'Code unavailable.'));
				});
			}
			locations.forEach(function (location, index) {
				var locked = allowed.indexOf(index) < 0;
				var button = element('button', 'wt-mini-chip wt-meta-chip wt-copy-chip wt-provider-location');
				button.type = 'button';
				button.setAttribute('aria-pressed', 'false');
				button.dataset.tip = location.file + ':' + location.startLine + '–' + location.endLine +
					(locked ? '. ' + lockedReason : '');
				button.appendChild(icon(locked ? 'lock' : 'code'));
				button.appendChild(element('span', '', shortLocation(location)));
				button.addEventListener('click', function () { open(index); });
				buttons.push(button);
				row.appendChild(button);
			});
			container.appendChild(row);
			container.appendChild(panel);
			if (allowed.length) open(allowed[0]);
		}
		function renderTechnical(detail, container) {
			var fold = element('details', 'wt-form-disclosure');
			fold.appendChild(element('summary', '', 'Technical details'));
			var body = element('div', 'wt-provider-ids');
			if (detail.findingId) body.appendChild(copyChip('AWS finding', detail.findingId));
			if (detail.jobId) body.appendChild(copyChip('AWS job', detail.jobId));
			if (detail.riskType) body.appendChild(element('span', '', 'AWS risk type: ' + words(detail.riskType)));
			[...new Set(detail.omissions || [])].filter(function (text) {
				return !text.startsWith('Provider narrative and source') && !text.startsWith('Provider title, description') &&
					!text.startsWith('Omitted narratives remain');
			}).forEach(function (text) { body.appendChild(element('span', 'wt-field-help', text)); });
			fold.appendChild(body);
			container.appendChild(fold);
		}
		function renderProvider(item, payload, container, chips) {
			var detail = payload.evidence || payload;
			if (payload.title && payload.title !== item.dataset.title) {
				item.dataset.title = payload.title;
				var rowTitle = item.querySelector('.wt-finding-item-topline strong');
				if (rowTitle) rowTitle.textContent = payload.title;
			}
			if (payload.title) detailTitle.textContent = payload.title;
			if (detail.locations && detail.locations.length) {
				var first = detail.locations[0];
				item.dataset.file = first.file; item.dataset.line = String(first.startLine);
				item.dataset.location = first.file;
				item.dataset.locationLabel = first.file + ':' + first.startLine;
				detailLocation.textContent = item.dataset.locationLabel;
				var rowLocation = item.querySelector('.wt-finding-location');
				if (rowLocation) rowLocation.textContent = first.file.split('/').pop() + ':' + first.startLine;
			}
			container.replaceChildren();
			if (chips) {
				chips.replaceChildren(
					chip('cloud', 'AWS Security Agent', 'Found by AWS Security Agent.' + (detail.riskType ? ' Risk type: ' + words(detail.riskType) + '.' : '')),
					chip('speed', 'Confidence: ' + (detail.confidence ? words(detail.confidence) : 'Not given'), 'How sure AWS is. Confidence is not a human check.'),
					validationChip(detail.validationStatus));
				chips.hidden = false;
			}
			if (payload.description) {
				detailGuidance.textContent = payload.description.split('\n\n')[0];
				var explanation = element('details', 'wt-form-disclosure');
				explanation.appendChild(element('summary', '', 'Read AWS’s full explanation'));
				explanation.appendChild(element('p', 'wt-provider-narrative', payload.description));
				if (payload.reasoning) {
					explanation.appendChild(element('h4', 'wt-meta-label', 'AWS reasoning'));
					explanation.appendChild(element('p', 'wt-provider-narrative', payload.reasoning));
				}
				container.appendChild(explanation);
			}
			renderLocations(item, detail, container);
			renderTechnical(detail, container);
		}
		function showProvider(item) {
			var container = workspace.querySelector('[data-provider-detail]');
			var chips = workspace.querySelector('[data-provider-chips]');
			var help = workspace.querySelector('[data-detail-help]');
			var isProvider = Boolean(item.dataset.providerDetailUrl);
			if (help) help.hidden = isProvider;
			if (chips) { chips.replaceChildren(); chips.hidden = true; }
			if (!container) return;
			container.replaceChildren();
			container.hidden = !isProvider;
			container.dataset.selected = item.id;
			if (!isProvider) return;
			var scannerChip = workspace.querySelector('[data-detail-scanner]');
			if (scannerChip) scannerChip.hidden = true;
			container.appendChild(element('p', 'wt-code-unavailable', 'Loading AWS details…'));
			fetch(item.dataset.providerDetailUrl, {credentials: 'same-origin', cache: 'no-store'}).then(function (response) {
				if (!response.ok) throw new Error('AWS details unavailable');
				return response.json();
			}).then(function (payload) {
				if (container.dataset.selected === item.id) renderProvider(item, payload, container, chips);
			}).catch(function () {
				if (container.dataset.selected === item.id) {
					container.replaceChildren(element('p', 'wt-code-unavailable', 'AWS details are unavailable. Reload the page or try again later.'));
				}
			});
		}

		function select(item, announceSource) {
            if (detailPanel) { detailPanel.hidden = false; detailPanel.inert = false; }
			if (detailPanel) {
				detailPanel.classList.add('is-updating');
				(window.requestAnimationFrame || window.setTimeout)(function () {
					detailPanel.classList.remove('is-updating');
				});
			}
			items.forEach(function (candidate) {
				var selected = candidate === item;
				candidate.classList.toggle('is-selected', selected);
				candidate.setAttribute('aria-pressed', String(selected));
			});
			// The AI assistant's page chip follows the chosen finding.
			document.dispatchEvent(new CustomEvent('wt:finding-selected'));

			detailTitle.textContent = item.dataset.title;
			detailLocation.textContent = item.dataset.locationLabel;
			detailGuidance.textContent = item.dataset.guidance;
			var scannerChip = workspace.querySelector('[data-detail-scanner]');
			if (scannerChip) {
				var scannerName = item.dataset.scannerName || '';
				scannerChip.hidden = !scannerName;
				scannerChip.querySelector('[data-detail-scanner-name]').textContent = scannerName;
				scannerChip.querySelector('[data-detail-scanner-icon]').textContent = item.dataset.scannerIcon || 'radar';
				scannerChip.dataset.tip = scannerName ? 'Found by ' + scannerName : '';
			}
			var review = workspace.querySelector('[data-detail-review]');
			if (review) {
				review.hidden = !item.dataset.feedbackKey;
				review.className = 'wt-mini-chip wt-review-chip--' + (item.dataset.reviewState || 'unreviewed');
				review.querySelector('[data-detail-review-icon]').textContent = item.dataset.reviewIcon || 'radio_button_unchecked';
				review.querySelector('[data-detail-review-label]').textContent = item.dataset.reviewLabel || 'Not reviewed';
			}
			var urlLabel = workspace.querySelector('[data-detail-url-label]');
			if (urlLabel) urlLabel.textContent = item.dataset.urlLabel || 'Documentation';
			var urlIcon = workspace.querySelector('[data-detail-url-icon]');
			if (urlIcon) urlIcon.textContent = item.dataset.providerDetailUrl ? 'open_in_new' : 'menu_book';
			var explain = workspace.querySelector('[data-detail-explain]');
			if (explain) {
				explain.hidden = !item.dataset.ruleId;
				explain.dataset.assistantExplain = item.dataset.ruleId || '';
			}
            var original = workspace.querySelector('[data-original-message]');
            if (original) {
                original.hidden = !item.dataset.originalGuidance;
                if (original.matches('details')) {
                    original.open = false;
                    original.querySelector('[data-original-guidance]').textContent = item.dataset.originalGuidance || '';
                } else {
                    // The Engine message chip: the message is its hover text and accessible name.
                    original.setAttribute('data-tip', item.dataset.originalGuidance || '');
                    original.setAttribute('aria-label', 'Engine message: ' + (item.dataset.originalGuidance || ''));
                }
            }
			// "Rule changed" / "Rule deleted": the guidance shown is read live from the rule.
			var ruleChange = workspace.querySelector('[data-rule-change]');
			if (ruleChange) {
				var changeLabel = item.dataset.ruleChangeLabel || '';
				var changeTip = item.dataset.ruleChangeTip || '';
				ruleChange.hidden = !changeLabel;
				ruleChange.setAttribute('data-tip', changeTip);
				ruleChange.setAttribute('aria-label', changeLabel + '. ' + changeTip);
				var changeText = ruleChange.querySelector('[data-rule-change-text]');
				if (changeText) changeText.textContent = changeLabel;
			}
			showProvider(item);
			detailSeverity.textContent = item.querySelector('.wt-sev').textContent;
			detailSeverity.className = item.querySelector('.wt-sev').className;

			var score = item.dataset.score || '';
			var vector = item.dataset.vector || '';
			detailCvss.hidden = !score && !vector;
			detailScore.textContent = score || 'Not provided';
			detailVectorRow.hidden = !vector;
			detailVector.textContent = vector;
			// Package (image) findings: CVSS and vector chips in plain words (UAT walkthrough).
			if (item.dataset.cvssLabel) {
				detailCvss.hidden = false;
				detailScore.textContent = item.dataset.cvssLabel;
				detailCvss.className = 'wt-sev wt-cvss-chip wt-sev-' + (item.dataset.cvssKey || 'UNKNOWN');
				detailCvss.dataset.tip = item.dataset.cvssTip || '';
				detailVector.textContent = item.dataset.vectorText || vector;
				detailVectorRow.dataset.tip = item.dataset.vectorTip || '';
			}
			copyButtons.forEach(function (button) {
				var field = button.dataset.copyFinding;
				button.dataset.copyValue = field === 'title' ? item.dataset.title :
					field === 'location' ? item.dataset.locationLabel : vector;
				button.hidden = field === 'vector' && !vector;
			});

			var url = item.dataset.url || '';
			detailUrl.hidden = !url;
			if (url) {
				detailUrl.href = url;
			}

			showVerification(item);
			showAction(item);

			var file = item.dataset.file || '';
			var line = item.dataset.line || '';
			var hasSourceAction = item.dataset.sourceAction === 'true';
			if (detailSource) {
				detailSource.hidden = !hasSourceAction;
				detailSource.dataset.file = file;
				detailSource.dataset.line = line;
			}
			workspace.dispatchEvent(new CustomEvent('wt:finding-selection', {bubbles: true}));
			if (hasSourceAction && announceSource) {
				workspace.dispatchEvent(new CustomEvent('wt:finding-selected', {
					bubbles: true,
					detail: {file: file, line: line, scroll: Boolean(announceSource)}
				}));
			}
		}

		function copyText(value) {
			if (navigator.clipboard && navigator.clipboard.writeText) {
				return navigator.clipboard.writeText(value);
			}
			var input = document.createElement('textarea');
			input.value = value;
			input.setAttribute('readonly', '');
			input.style.position = 'fixed';
			input.style.opacity = '0';
			document.body.appendChild(input);
			input.select();
			var copied = document.execCommand('copy');
			input.remove();
			return copied ? Promise.resolve() : Promise.reject(new Error('Copy unavailable'));
		}

		function renderPage() {
			var pageCount = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE));
			currentPage = Math.min(currentPage, pageCount - 1);
			var start = currentPage * PAGE_SIZE;
			var end = Math.min(start + PAGE_SIZE, filteredItems.length);
			var pageItems = filteredItems.slice(start, end);

			items.forEach(function (item) {
				item.hidden = !pageItems.includes(item);
			});
			empty.hidden = filteredItems.length !== 0;
			range.textContent = filteredItems.length ?
				(start + 1) + '\u2013' + end + ' of ' + filteredItems.length : '0 of 0';
			previous.disabled = currentPage === 0;
			next.disabled = currentPage >= pageCount - 1 || filteredItems.length === 0;
			previous.setAttribute('aria-disabled', String(previous.disabled));
			next.setAttribute('aria-disabled', String(next.disabled));

			var selected = pageItems.find(function (item) {
				return item.classList.contains('is-selected');
			});
            if (!pageItems.length) {
                items.forEach(item => { item.classList.remove('is-selected'); item.setAttribute('aria-pressed', 'false'); });
                if (detailPanel) { detailPanel.hidden = true; detailPanel.inert = true; }
                [detailTitle, detailLocation, detailGuidance, detailScore, detailVector].forEach(node => { if (node) node.textContent = ''; });
                [detailAction, detailSource, detailUrl].forEach(node => { if (node) node.removeAttribute('href'); });
                copyButtons.forEach(button => { button.dataset.copyValue = ''; });
                var evidence = workspace.querySelector('[data-provider-detail]');
                if (evidence) { evidence.dataset.selected = ''; evidence.replaceChildren(); }
                workspace.dispatchEvent(new CustomEvent('wt:finding-cleared', {bubbles: true}));
            }
			if (!selected && pageItems.length) {
				select(pageItems[0], false);
			} else if (selected && selected.dataset.providerDetailUrl) {
                var evidence = workspace.querySelector('[data-provider-detail]');
                if (evidence && evidence.dataset.selected !== selected.id) select(selected, false);
            }
			if (listViewport) {
				listViewport.scrollTop = 0;
			}
		}

		function filter() {
			var query = normalized(search.value);
			currentPage = 0;
			filteredItems = items.filter(function (item) {
				var haystack = normalized([
					item.dataset.title,
					item.dataset.guidance,
					item.dataset.locationLabel
				].join(' '));
				var matches = (!query || haystack.includes(query)) &&
					(!shownSeverities() || shownSeverities().indexOf(item.dataset.severity) >= 0) &&
					(!location.value || item.dataset.location === location.value) &&
					(!scanner || !scanner.value || item.dataset.scannerGroup === scanner.value);
				return matches;
			});

			severityChips.forEach(function (chip) {
				var shown = shownSeverities();
				var pressed = !shown || shown.indexOf(chip.dataset.severityChip) >= 0;
				chip.setAttribute('aria-pressed', String(pressed));
				chip.classList.toggle('is-dimmed', !pressed);
			});
			var countLabel = filteredItems.length +
				(filteredItems.length === 1 ? ' finding' : ' findings');
			status.textContent = countLabel;
			if (total) {
				total.textContent = countLabel;
			}
			showScannerEmpty();
			renderPage();
		}

		var awsTitlesUrl = workspace.closest('[data-aws-titles-url]');
		if (awsTitlesUrl) {
			fetch(awsTitlesUrl.dataset.awsTitlesUrl, {credentials: 'same-origin', cache: 'no-store'})
				.then(function (response) { if (!response.ok) throw new Error('AWS details unavailable'); return response.json(); })
				.then(function (headlines) {
					items.forEach(function (item) {
						var headline = headlines[item.id.replace(/^aws-/, '')];
						if (!headline) return;
						item.dataset.title = headline.title;
						var rowTitle = item.querySelector('.wt-finding-item-topline strong');
						if (rowTitle) rowTitle.textContent = headline.title;
						if (headline.file && headline.line) {
							item.dataset.file = headline.file; item.dataset.line = String(headline.line);
							item.dataset.location = headline.file;
							item.dataset.locationLabel = headline.file + ':' + headline.line;
							var rowLocation = item.querySelector('.wt-finding-location');
							if (rowLocation) rowLocation.textContent = headline.file.split('/').pop() + ':' + headline.line;
						}
						if (item.classList.contains('is-selected')) {
							detailTitle.textContent = item.dataset.title;
							detailLocation.textContent = item.dataset.locationLabel;
						}
					});
					locationValues.splice(0, locationValues.length, ...Array.from(new Set(items.map(function (item) { return item.dataset.location; })))
						.filter(Boolean).sort(function (a, b) { return a.localeCompare(b); }));
					if (locationMenu) {
						var options = locationMenu.querySelector('[data-finding-location-options]');
						options.querySelectorAll('.wt-menu-item--path').forEach(function (option) { option.remove(); });
						locationValues.forEach(function (value) {
							var option = document.createElement('button'); option.type = 'button';
							option.className = 'wt-menu-item wt-menu-item--path'; option.setAttribute('role', 'menuitemradio');
							option.setAttribute('aria-checked', 'false'); option.value = value; option.textContent = value;
							options.appendChild(option);
						});
						locationMenu.querySelector('[data-finding-location-count]').textContent = String(locationValues.length);
					} else {
						Array.from(location.children).slice(1).forEach(function (option) { option.remove(); });
						locationValues.forEach(function (value) {
							var material = location.tagName.toLowerCase() === 'md-outlined-select';
							var option = document.createElement(material ? 'md-select-option' : 'option'); option.value = value;
							if (material) { var label = document.createElement('div'); label.slot = 'headline'; label.textContent = value; option.appendChild(label); }
							else option.textContent = value;
							location.appendChild(option);
						});
					}
					location.value = ''; showLocationChoice(); filter();
				}).catch(function () { /* Saved metadata remains available without AWS. */ });
		}

		items.forEach(function (item) {
			item.addEventListener('click', function () { select(item, false); });
		});
		copyButtons.forEach(function (button) {
			button.addEventListener('click', function () {
				var value = button.dataset.copyValue || '';
				if (!value) {
					return;
				}
				copyText(value).then(function () {
					copyStatus.textContent = 'Copied to clipboard.';
				}).catch(function () {
					copyStatus.textContent = 'Copy failed. Select and copy the value manually.';
				});
			});
		});
		search.addEventListener('input', filter);
		severity.addEventListener('change', filter);
		severityChips.forEach(function (chip) {
			chip.addEventListener('click', function () {
				var visible = shownSeverities() || allSeverities.slice();
				var key = chip.dataset.severityChip;
				visible = visible.indexOf(key) >= 0 ? visible.filter(function (k) { return k !== key; }) : visible.concat([key]);
				severity.value = visible.length === allSeverities.length ? ''
					: (visible.length ? allSeverities.filter(function (k) { return visible.indexOf(k) >= 0; }).join(',') : '-');
				filter();
			});
		});
		location.addEventListener('change', filter);
		previous.addEventListener('click', function () {
			if (currentPage > 0) {
				currentPage -= 1;
				renderPage();
			}
		});
		next.addEventListener('click', function () {
			if ((currentPage + 1) * PAGE_SIZE < filteredItems.length) {
				currentPage += 1;
				renderPage();
			}
		});
		var returnContext = new URLSearchParams(window.location.search);
		if (returnContext.has('reviewSearch')) search.value = returnContext.get('reviewSearch');
		if (returnContext.has('reviewSeverity')) severity.value = returnContext.get('reviewSeverity');
		if (returnContext.has('reviewLocation')) location.value = returnContext.get('reviewLocation');
		showLocationChoice();
		filter();
		var returnKey = returnContext.get('reviewFinding');
		var returnIndex = returnKey ? filteredItems.findIndex(function (item) { return item.dataset.feedbackKey === returnKey; }) : -1;
		if (returnIndex >= 0) {
			currentPage = Math.floor(returnIndex / PAGE_SIZE);
			renderPage();
			select(filteredItems[returnIndex], false);
		}
	}

	document.querySelectorAll('[data-finding-workspace]').forEach(initialize);
})();

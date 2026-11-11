package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

class ExperienceFoundationMarkupTest {
	private static final List<String> AUTH_TEMPLATES = List.of(
			"watchtower-web/src/main/resources/templates/login.html",
			"watchtower-web/src/main/resources/templates/login-sso.html",
			"watchtower-web/src/main/resources/templates/register.html");
	// Pull request results use the shared scan activity table (fragments/scanactivity) since the
	// Fixes board (2026-10-22), like Home and Repository results; they are checked separately.
	private static final String PR_RESULTS = "watchtower-core/src/main/resources/templates/pull_requests/results.html";
	private static final List<String> RESULT_TEMPLATES = List.of(
			"watchtower-core/src/main/resources/templates/pull_requests/mcrs.html",
			"watchtower-core/src/main/resources/templates/upload_scan/results.html",
			"watchtower-core/src/main/resources/templates/image_scan/results.html");
	private static final List<String> SUBMISSION_TEMPLATES = List.of(
			"watchtower-core/src/main/resources/templates/pull_requests/submitscan.html",
			"watchtower-core/src/main/resources/templates/upload_scan/submitscan.html");
	private static final List<String> RULE_DESIGNER_TEMPLATES = List.of(
			"watchtower-module-eslint/src/main/resources/templates/designer/eslint.html",
			"watchtower-module-json/src/main/resources/templates/designer/json.html",
			"watchtower-module-pmd/src/main/resources/templates/designer/pmd.html",
			"watchtower-module-regex/src/main/resources/templates/designer/regex.html");
	private static final List<String> DASHBOARD_TEMPLATES = List.of(
			"watchtower-core/src/main/resources/templates/pull_requests/dashboard.html",
			"watchtower-core/src/main/resources/templates/upload_scan/dashboard.html",
			"watchtower-core/src/main/resources/templates/image_scan/dashboard.html");

	@Test
	void sharedPageHeaderProvidesOneH1AndListBreadcrumb() throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/fragments/pageheader.html");
		Document pageHeader = Jsoup.parse(source);

		assertEquals(1, pageHeader.select("h1.page-title").size());
		assertNotNull(pageHeader.selectFirst("nav[aria-label=Breadcrumb] ol"));
		assertNotNull(pageHeader.selectFirst("nav[aria-label=Breadcrumb] a[th:href]"));
		assertNotNull(pageHeader.selectFirst("nav[aria-label=Breadcrumb] li[aria-current=page]"));
		assertTrue(source.contains("breadcrumbLinks"));
	}

	@Test
	void resultEntityLinksUseTheSharedQuietLinkTreatment() throws IOException {
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/pull_requests/mcrs.html",
				"watchtower-core/src/main/resources/templates/fragments/scanactivity.html")) {
			assertNotNull(parse(template).selectFirst("a.wt-entity-link"), template);
		}
		// The PR report's facts are icon chips now (UAT walkthrough 2026-10-15); its link is one, and so is the MCR report's.
		for (String template : List.of("watchtower-core/src/main/resources/templates/pull_requests/scanreport.html",
				"watchtower-core/src/main/resources/templates/pull_requests/mcrreport.html")) {
			assertNotNull(parse(template).selectFirst("a.wt-meta-chip.wt-mini-chip--link[target=_blank]"), template);
		}
		String css = read(
				"watchtower-core/src/main/resources/static/styles/components.css");
		assertTrue(css.contains(".wt-entity-link"));
	}

	@Test
	void reportsOpenWithOneHeaderLineInsteadOfSummaryCards() throws IOException {
		// docs/design-system.md "Restraint": the summary/performance cockpit cards became one
		// line (.wt-report-bar), and their styles were removed with them.
		String css = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		assertTrue(css.contains(".wt-report-bar"));
		assertTrue(css.contains(".wt-report-meta"));
		assertFalse(css.contains(".wt-report-cockpit"));
		assertFalse(css.contains(".wt-report-summary"));
	}

	@Test
	void homeHealthSummaryExposesScannersConnectionsAndWorkload() throws IOException {
		Document dashboard = parse(
				"watchtower-core/src/main/resources/templates/metricsdashboard.html");

		assertNotNull(dashboard.selectFirst("[data-health-scanners]"));
		assertNotNull(dashboard.selectFirst("[data-health-connections]"));
		// Workload is shown once, by the live workload fragment, not repeated in the health line.
		assertEquals(0, dashboard.select("[data-health-workload]").size());
		assertTrue(read("watchtower-core/src/main/resources/templates/metricsdashboard.html")
				.contains("fragments/scanworkload :: workload"));
	}

	@Test
	void paginationUsesNonLinksAtBothBoundariesAndAnnouncesUpdates() throws IOException {
		String source = read("watchtower-core/src/main/resources/templates/fragments/pagination.html");
		Document pagination = Jsoup.parse(source);

		assertNotNull(pagination.selectFirst("[aria-label=Pagination]"));
		assertNotNull(pagination.selectFirst("[aria-current=page]"));
		assertTrue(source.contains("<span th:if=\"${!pagination.hasPrevious()}\""));
		assertTrue(source.contains("<span th:if=\"${!pagination.hasNext()}\""));
		assertFalse(source.contains("<a th:if=\"${!pagination.hasPrevious()}\""));
		assertTrue(source.contains("pagination.firstElementNumber()"));
		assertTrue(source.contains("pagination.totalElements()"));
		assertNotNull(pagination.selectFirst("[role=status][aria-live=polite]"));
		assertNotNull(pagination.selectFirst(".wt-pagination__step .material-icons"));
		assertNotNull(pagination.selectFirst(".wt-pagination__page[aria-current=page]"));
		assertEquals(0, pagination.select(".wt-pagination .btn").size());
	}

	@Test
	void tablesShareConsistentGuttersAndVerticalAlignment() throws IOException {
		String tokens = read(
				"watchtower-core/src/main/resources/static/styles/tokens.css");
		String components = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		assertTrue(tokens.contains("--wt-table-cell-padding-block: var(--wt-space-3)"));
		assertTrue(tokens.contains("--wt-table-cell-padding-inline: var(--wt-space-4)"));
		assertTrue(tokens.contains("--wt-table-header-bg: linear-gradient"));
		assertTrue(components.contains(".table > :not(caption) > * > *"));
		assertTrue(components.contains("padding: var(--wt-table-cell-padding-block)"
				+ " var(--wt-table-cell-padding-inline)"));
		assertTrue(components.contains(".table > caption"));
		assertTrue(components.contains("padding-inline: var(--wt-table-cell-padding-inline)"));
		assertTrue(components.contains(".table > tbody > tr"));
		assertTrue(components.contains("block-size: var(--wt-table-row-min-height)"));
		assertTrue(components.contains("background: var(--wt-table-header-bg)"));
	}

	@Test
	void authenticationPagesUseLightweightHeadMainAndPasswordManagerSemantics() throws IOException {
		for (String template : AUTH_TEMPLATES) {
			String source = read(template);
			Document document = Jsoup.parse(source);
			assertTrue(source.contains("fragments/authhead"), template);
			assertNotNull(document.selectFirst("main"), template);
			assertEquals(1, document.select("h1").size(), template);
		}

		Document login = parse(AUTH_TEMPLATES.get(0));
		assertNotNull(login.selectFirst("#login-error[role=alert]"));
		org.jsoup.nodes.Element username = login.selectFirst(
				"[name=username][autocomplete=username]");
		org.jsoup.nodes.Element password = login.selectFirst(
				"[name=password][autocomplete=current-password]");
		assertNotNull(username);
		assertNotNull(password);
		assertTrue(username.hasAttr("th:value"));
		assertTrue(username.hasAttr("th:attr"));
		assertTrue(password.hasAttr("th:attr"));

		Document registration = parse(AUTH_TEMPLATES.get(2));
		assertEquals(2, registration.select("[type=password][autocomplete=new-password]").size());
	}

	@Test
	void authenticationHeadDoesNotLoadApplicationOnlyLibraries() throws IOException {
		String head = read("watchtower-core/src/main/resources/templates/fragments/authhead.html");
		assertFalse(head.contains("jquery"));
		assertFalse(head.contains("chart.js"));
		assertFalse(head.contains("datatables"));
		assertFalse(head.contains("luxon"));
	}

	@Test
	void htmxNavigationUpdatesTitleAndFocusesThePageHeading() throws IOException {
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/loading-indicator.js");
		assertTrue(script.contains("document.title"));
		assertFalse(script.contains("[data-shell-page-title]"));
		assertTrue(script.contains("heading.focus"));
		assertTrue(script.contains("htmx:afterSettle"));
		assertTrue(script.contains("htmx:afterSwap"));
		assertTrue(script.contains("htmx:historyRestore"));
	}

	@Test
	void shellOmitsTheContentHeaderAndKeepsAccountAndMobileNavigationAvailable()
			throws IOException {
		String containerSource = read(
				"watchtower-core/src/main/resources/templates/fragments/container.html");
		Document container = Jsoup.parse(containerSource);
		Document sidebar = parse(
				"watchtower-core/src/main/resources/templates/fragments/sidebar.html");

		assertFalse(containerSource.contains("fragments/topnavbar"));
		assertEquals(0, container.select(".main-content > .main-navbar").size());
		assertNotNull(container.selectFirst(
				".main-content > button[data-wt-drawer-trigger]"
						+ "[aria-controls=main-navigation][aria-expanded=false]"));
		assertNotNull(sidebar.selectFirst("aside#main-navigation"));
		assertNotNull(sidebar.selectFirst(".wt-sidebar-account wt-user-menu"));
		assertNotNull(sidebar.selectFirst(".wt-sidebar-account [data-sidebar-username]"));
		assertNotNull(sidebar.selectFirst(".wt-sidebar-account form[action=/logout]"));
	}

	@Test
	void reportMetadataAndCommandSearchUseValidAccessibleStructure() throws IOException {
		Document performance = parse(
				"watchtower-core/src/main/resources/templates/fragments/prscanperformance.html");
		Document mcr = parse(
				"watchtower-core/src/main/resources/templates/pull_requests/mcrreport.html");
		Document execution = parse(
				"watchtower-core/src/main/resources/templates/fragments/scanexecution.html");
		String commandPalette = read(
				"watchtower-core/src/main/frontend/material-web/src/components/wt-command-palette.js");

		assertEquals(0, performance.select("dl > small, dl > div > small").size());
		assertEquals(0, performance.select(".wt-performance-disclosure").size());
		// The MCR report opens like the PR report: the review status as a chip by the title, the
		// facts as chips, and the status form in a dialog; no cards above the findings.
		assertNotNull(mcr.selectFirst(".wt-report-head .wt-report-head__status"));
		assertNotNull(mcr.selectFirst(".wt-meta-chips a.wt-mini-chip--link[target=_blank]"));
		assertNotNull(mcr.selectFirst(".wt-report-status md-outlined-button[data-wt-dialog-open=#mcrStatusDialog]"));
		assertNotNull(mcr.selectFirst("md-dialog#mcrStatusDialog form[data-mcr-status] md-outlined-select[name=mcrstatus]"));
		assertEquals(0, mcr.select(".card, .wt-report-bar").size());
		assertEquals(1, mcr.select("md-filled-button").size());
		assertNotNull(execution.selectFirst(".wt-scan-execution-inline"));
		assertTrue(commandPalette.contains("id=\"wt-command-search\""));
		assertTrue(commandPalette.contains("name=\"commandSearch\""));
	}

	@Test
	void pullRequestResultsUseTheSharedActivityTableWithFiltersAndAnEmptyState() throws IOException {
		String source = read(PR_RESULTS);
		assertTrue(source.contains("fragments/resultfilters"));
		assertTrue(source.contains("fragments/scanactivity :: table("));
		assertTrue(source.contains("#lists.isEmpty(results)"));
		assertTrue(source.contains("fragments/emptystate :: state"));
		assertFalse(source.contains("More scan details"));
		Document activity = Jsoup.parse(read("watchtower-core/src/main/resources/templates/fragments/scanactivity.html"));
		assertNotNull(activity.selectFirst(".localizetime[data-time-style=short]"), "short Finished time");
		assertNotNull(activity.selectFirst("table.wt-activity-table > caption.visually-hidden"), "no visible caption");
		assertFalse(read("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.contains("providerFindingCount + ' ' + activity.providerLabel"), "no \"+19 AWS\" chip");
	}

	@Test
	void resultListsUseSharedSegmentedFiltersCaptionsAndContainedTables() throws IOException {
		for (String template : RESULT_TEMPLATES) {
			String source = read(template);
			Document document = Jsoup.parse(source);
			assertTrue(source.contains("fragments/resultfilters"), template);
			assertFalse(source.contains("Select a Filter"), template);
			assertEquals(document.select("table").size(), document.select("table > caption").size(),
					template);
			assertEquals(document.select("table").size(), document.select(".wt-table-scroll > table").size(),
					template);
			assertTrue(document.select("tbody > tr.wt-result-row").size() > 0, template);
			// The narrow-screen detail row is inline chips with a short time, not a "More scan
			// details" fold (UAT walkthrough, 2026-10-16).
			assertTrue(document.select("tbody > tr.wt-result-detail-row .wt-meta-chips > .wt-mini-chip").size() > 0,
					template);
			assertEquals(0, document.select("tr.wt-result-detail-row details").size(), template);
			assertFalse(source.contains("More scan details") || source.contains("More review details"), template);
			assertNotNull(document.selectFirst("tr.wt-result-detail-row .localizetime[data-time-style=short]"), template);
			assertTrue(document.select(".wt-result-identity").size() > 0, template);
			assertTrue(document.select(".wt-result-status .wt-status-chip").size() > 0, template);
			assertTrue(document.select(".wt-result-findings").size() > 0, template);
			assertTrue(document.select(".wt-result-action").size() > 0, template);
			// An empty filter says so, instead of an empty table (Thymeleaf treats an empty
			// list as true, so th:if="${results}" alone never hid it).
			assertTrue(source.contains("#lists.isEmpty(results)"), template);
			assertTrue(source.contains("fragments/emptystate :: state"), template);
			assertFalse(source.contains("Viewer'"), template);
		}

		// Upload and image results: Duration, a short Finished time (full time on hover), the
		// report button last, and the image registry as a chip.
		for (String template : List.of("watchtower-core/src/main/resources/templates/upload_scan/results.html",
				"watchtower-core/src/main/resources/templates/image_scan/results.html")) {
			Document document = Jsoup.parse(read(template));
			assertTrue(document.select("thead th").eachText().contains("Duration"), template);
			assertNotNull(document.selectFirst(".localizetime[data-time-style=short]"), template);
			assertNotNull(document.selectFirst("tr.wt-result-row > td:last-child .wt-report-link"), template);
		}
		assertNotNull(Jsoup.parse(read("watchtower-core/src/main/resources/templates/image_scan/results.html"))
				.selectFirst("td .wt-mini-chip[data-tip=Registry integration]"));

		String styles = read("watchtower-core/src/main/resources/static/styles/components.css");
		assertTrue(styles.contains(".wt-result-detail-row"));
		assertTrue(styles.contains(".wt-result-secondary"));
	}

	@Test
	void componentPreviewExposesSemanticStatesAndResponsiveExamples() throws IOException {
		Document preview = parse(
				"watchtower-core/src/main/resources/templates/admin/ui-components.html");

		assertEquals(1, preview.select("h1").size());
		assertNotNull(preview.selectFirst("[data-preview=themes]"));
		assertNotNull(preview.selectFirst("[data-preview=focus-states]"));
		assertNotNull(preview.selectFirst("[data-preview=density]"));
		assertNotNull(preview.selectFirst("[data-preview=responsive-table] table > caption"));
		assertNotNull(preview.selectFirst("[role=status][aria-live=polite]"));
		assertNotNull(preview.selectFirst("[role=alert]"));
		// Restraint (docs/design-system.md): hide what the viewer can't use, so the gallery no
		// longer shows a disabled primary button; it shows the patterns that replace blocks.
		assertNull(preview.selectFirst("md-filled-button[disabled]"));
		assertNotNull(preview.selectFirst("[data-preview=restraint] .wt-page-bar .wt-status-chip"));
		assertNotNull(preview.selectFirst("[data-preview=restraint] details.wt-popover .wt-popover__body"));
		assertNotNull(preview.selectFirst("[data-preview=restraint] .wt-row-action.wt-row-action--danger"));
		assertNotNull(preview.selectFirst("[data-preview=restraint] details.wt-form-disclosure"));
		assertNotNull(preview.selectFirst("[data-preview=restraint] form[data-confirm][data-confirm-action]"));
		assertNotNull(preview.selectFirst("[aria-busy=true]"));
		assertTrue(preview.select("md-filled-button, md-outlined-button, md-text-button")
				.size() >= 8);
		assertEquals(2, preview.select("md-outlined-text-field").size());
		assertEquals(0, preview.select("button.btn, input.form-control").size());
	}

	@Test
	void homeProvidesOverviewModuleActionsAndRecentActivityTable() throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/metricsdashboard.html");
		Document home = Jsoup.parse(source);

		// One line for the last 30 days and one line per module above the table: no tiles,
		// no module cards, no filled buttons (the sidebar already leads to each module).
		// The 30-day numbers: four compact stat boxes in one row (not the old full-size tiles).
		assertEquals(4, home.select("[data-home-overview] .wt-stat-box").size());
		assertEquals(0, home.select(".wt-kpi, .wt-module-card").size());
		// "Total scans" (UAT walkthrough 2026-10-15): one table row per scan type, each with its
		// sidebar icon and the same Dashboard / Results / New scan actions (images: Automatic).
		assertEquals("total : ${homeTotals}", home.selectFirst("tr[data-home-module]").attr("th:each"));
		assertEquals(1, home.select("[data-home-module] th .material-icons").size());
		assertNotNull(home.selectFirst("[data-home-module] .wt-home-totals__actions .wt-mini-chip--auto"));
		assertNotNull(home.selectFirst("details[data-home-status] > summary"));
		// The activity table is shared with the scan dashboards (fragments/scanactivity).
		assertTrue(source.contains("fragments/scanactivity :: table(${recentActivity}"));
		assertNotNull(parse("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.selectFirst("table > caption + thead + tbody .wt-scanner-tiles"));
		assertEquals(0, home.select("md-filled-button, .btn-primary").size());
		assertFalse(source.contains("durable metric projections"));
		assertTrue(source.indexOf("fragments/scanworkload") < source.indexOf("fragments/scanactivity"),
				"the live workload sits above the activity table");
		assertNotNull(home.selectFirst("table > caption"));
		assertNotNull(parse("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.selectFirst("a.wt-report-link .material-icons"));
		assertNotNull(home.selectFirst("[data-home-activity-empty]"));
		assertTrue(source.contains("sec:authorize"));
	}

	@Test
	void chartLibraryIsRouteScopedInsteadOfGlobal() throws IOException {
		String head = read(
				"watchtower-core/src/main/resources/templates/fragments/htmlhead.html");
		assertFalse(head.contains("chart.umd.js"));

		for (String controller : List.of(
				"watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/scan/code/scm/pr/controller/PRDashboardController.java",
				"watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/scan/code/upload/controller/UploadDashboardController.java",
				"watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/scan/image/controller/ImageScanDashboardController.java")) {
			String source = read(controller);
			assertTrue(source.indexOf("chart.umd.js") < source.indexOf("dashboard/utils.js"),
					controller);
			assertTrue(source.contains("dashboard/dashboard-stats-switcher.js"), controller);
		}
	}

	@Test
	void dashboardsShareOneRangeControlAndAccessibleInsights() throws IOException {
		Document charts = parse(
				"watchtower-core/src/main/resources/templates/fragments/dashboard.html");

		assertEquals(1, charts.select("[data-dashboard-range]").size());
		// "Preparing metrics" is a chip next to the heading, not a banner above the charts.
		assertNotNull(charts.selectFirst(".wt-dashboard-toolbar .wt-status-chip[data-metrics-preparing][role=status]"));
		assertEquals(0, charts.select(".alert, .wt-eyebrow").size());
		assertNotNull(charts.selectFirst("[data-dashboard-tabs][role=tablist]"));
		assertEquals(2, charts.select("[data-dashboard-tabs] [role=tab]").size());
		assertEquals(2, charts.select(".wt-dashboard-metric-view[role=tabpanel]").size());
		assertNotNull(charts.selectFirst("#dashboard-activity-view #scans-trend"));
		assertNotNull(charts.selectFirst("#dashboard-activity-view #findings-trend"));
		assertNotNull(charts.selectFirst("#dashboard-performance-view #performance-trend"));
		assertEquals(3, charts.select("canvas[role=img][aria-label]").size());
		assertEquals(3, charts.select("[data-chart-state][role=status][aria-live=polite]").size());
		assertEquals(3, charts.select("[data-chart-region][aria-busy]").size());
		assertEquals(1, charts.select("[data-dashboard-distribution]").size());
		assertEquals(2, charts.select("[data-dashboard-chart-frame]").size());
		assertEquals(0, charts.select("[data-custom-range-for=dashboard-period]").size());
		assertEquals(0, charts.select("#line-period, #pie-period, #bar-period").size());
		assertNotNull(charts.selectFirst("section.wt-recent-scans .wt-table-scroll > div[th:replace]"));
		assertTrue(read("watchtower-core/src/main/resources/templates/fragments/dashboard.html")
				.contains("fragments/scanactivity :: table(${recentScans}"));

		for (String template : DASHBOARD_TEMPLATES) {
			String source = read(template);
			assertTrue(source.contains("fragments/dashboard :: insights"), template);
			assertTrue(source.contains("fragments/dashboard :: recentScans"), template);
			assertFalse(source.contains("id=\"statsbtn\""), template);
			// The charts start at the top: no all-time tiles repeating the period's numbers.
			assertFalse(source.contains("wt-kpi"), template);
			assertFalse(source.contains("id=\"line-period\""), template);
			assertFalse(source.contains("id=\"pie-period\""), template);
			assertFalse(source.contains("id=\"bar-period\""), template);
		}
	}

	@Test
	void dashboardRangeAndRankedFindingsExposeMaterialControlsAndScrollAffordance()
			throws IOException {
		Document dashboard = parse(
				"watchtower-core/src/main/resources/templates/fragments/dashboard.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/dashboard/dashboard-insights.js");

		// Approved board (2026-10-22): 7 days / 30 days / 6 months / All time / Custom; starts on 30 days.
		assertNotNull(dashboard.selectFirst("input[type=hidden]#dashboard-period[value=last-thirty-days]"));
		assertNotNull(dashboard.selectFirst(
				".wt-segmented-filter[role=group][aria-label='Date range'][data-dashboard-range-options]"));
		assertEquals(java.util.List.of("last-week", "last-thirty-days", "last-six-months", "all-time", "custom"),
				dashboard.select("[data-dashboard-range-options] > button.wt-segment[data-period]").eachAttr("data-period"));
		assertEquals(5, dashboard.select("[data-dashboard-range-options] > button > .material-icons").size(),
				"every option carries an icon");
		assertEquals(1, dashboard.select("[data-dashboard-range-options] > [aria-pressed=true]").size());
		assertNotNull(dashboard.selectFirst("[data-dashboard-range-options] > [data-period=custom]"));
		assertEquals(0, dashboard.select("[data-custom-range-for=dashboard-period]").size());
		assertEquals(0, dashboard.select("md-outlined-select#dashboard-period").size());
		assertNotNull(dashboard.selectFirst(
				"[data-dashboard-distribution][tabindex=0][aria-label]"));
		// "All N rules" replaces the scroll box and its "Scroll for more findings" hint.
		assertNotNull(dashboard.selectFirst("button[data-dashboard-show-all][aria-expanded=false][hidden]"));
		assertEquals(0, dashboard.select("[data-dashboard-scroll-hint]").size());
		assertTrue(script.contains("isDaily("));
		assertTrue(script.contains("tension: 0"));
		assertFalse(script.contains("tension: 0.25"), "no curved lines between points");
		String utilities = read(
				"watchtower-core/src/main/resources/static/scripts/dashboard/utils.js");
		assertTrue(utilities.contains("document.createElement('md-outlined-text-field')"));
		assertFalse(utilities.contains("document.createElement('input')"));
	}

	@Test
	void pullRequestPerformanceIsPartOfTheSharedTrendWorkspace() throws IOException {
		Document dashboard = parse(
				"watchtower-core/src/main/resources/templates/fragments/dashboard.html");
		String pullRequestDashboard = read(
				"watchtower-core/src/main/resources/templates/pull_requests/dashboard.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/dashboard/dashboard-insights.js");

		assertNotNull(dashboard.selectFirst(
				"canvas#performance-trend[role=img][aria-label]"));
		assertNotNull(dashboard.selectFirst("[data-dashboard-total=performance]"));
		assertFalse(pullRequestDashboard.contains("PR scan performance diagnostics"));
		assertFalse(pullRequestDashboard.contains("recentPerformance"));
		assertTrue(script.contains("/rest/metrics/pr-performance-by-period"));
		assertTrue(script.contains("renderPerformanceTrend"));
		assertTrue(script.contains("scannerSeries"));
	}

	@Test
	void pullRequestSubmissionPaginatesRecentScansAndAlignsScannerStatus() throws IOException {
		Document submission = parse(
				"watchtower-core/src/main/resources/templates/pull_requests/submitscan.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/scan-submission.js");
		String styles = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		// The five newest scans in Home's shared table (plus each PR's State) and a link to all results.
		String source = read("watchtower-core/src/main/resources/templates/pull_requests/submitscan.html");
		assertNotNull(submission.selectFirst("[data-recent-scan-list]"));
		assertNotNull(submission.selectFirst("[data-recent-scan-list] [th:with='showState=true']"));
		assertTrue(source.contains("fragments/scanactivity :: table(${recentActivity}"));
		assertNotNull(submission.selectFirst("[data-recent-scan-list] a[href=/scan/results/all]"));
		assertEquals(0, submission.select("[data-recent-scan-pagination]").size());
		assertFalse(script.contains("RECENT_SCAN_PAGE_SIZE"));
		assertTrue(read("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.contains("th:if=\"${withState}\">State</th>"));
		// Scanner state is a chip line (shared with Upload) with the controls behind one button.
		assertTrue(source.contains("fragments/scannerstate :: chips("));
		Document state = parse("watchtower-core/src/main/resources/templates/fragments/scannerstate.html");
		assertNotNull(state.selectFirst(".wt-status-chip[data-scanner-state][th:attr^=data-tip]"));
		assertEquals(2, state.select(".wt-mini-chip[th:attr^=data-tip] > .material-icons").size(),
				"waiting and running are icon counts with their meaning on hover");
		// A labelled "Scanner controls" button (the icon alone was easy to miss).
		assertTrue(submission.selectFirst(".wt-page-bar details.wt-popover summary").text()
				.contains("Scanner controls"));
		assertEquals(0, submission.select(".wt-scanner-panel, .wt-field-help").size());
		assertTrue(styles.contains(".wt-submission-form"));
	}

	@Test
	void submissionPagesUseAccessibleFormsAdminDisclosureAndSharedTables() throws IOException {
		for (String template : SUBMISSION_TEMPLATES) {
			String source = read(template);
			Document document = Jsoup.parse(source);

			assertNotNull(document.selectFirst("form[data-scan-submission]"), template);
			assertNotNull(document.selectFirst("[role=status][aria-live=polite]"), template);
			assertNotNull(document.selectFirst("details.wt-admin-disclosure"), template);
			// Admin pause/quiesce confirm through confirm-action.js, with a named action.
			assertEquals(2, document.select("details.wt-admin-disclosure form").size(), template);
			assertEquals(2, source.split("th:data-confirm-action=", -1).length - 1, template);
			assertEquals(2, document.select(".card").size(), template + ": the form and recent scans");
			assertFalse(source.contains("Scan ID"), template);
			assertEquals(document.select("table").size(),
					document.select("table > caption").size(), template);
			assertEquals(document.select("table").size(),
					document.select(".wt-table-scroll > table").size(), template);
			assertFalse(source.contains("datatable-invert"), template);
		}
	}

	@Test
	void uploadSubmissionKeepsAnAccessibleNativeFileInputAndDropZone() throws IOException {
		Document upload = parse(SUBMISSION_TEMPLATES.get(1));

		assertNotNull(upload.selectFirst(".wt-drop-zone"));
		assertNotNull(upload.selectFirst(
				"input[type=file][accept][required][aria-describedby]"));
	}

	@Test
	void dateLocalizationAndReportPathWrappingUseNativeBrowserApis() throws IOException {
		String head = read(
				"watchtower-core/src/main/resources/templates/fragments/htmlhead.html");
		String localization = read(
				"watchtower-core/src/main/resources/static/scripts/localizetime.js");
		String report = read(
				"watchtower-core/src/main/resources/static/scripts/scan_report.js");

		assertFalse(head.contains("luxon"));
		assertFalse(localization.contains("$("));
		assertFalse(localization.contains("luxon"));
		assertTrue(localization.contains("Intl.DateTimeFormat"));
		assertTrue(localization.contains("htmx:afterSwap"));
		assertTrue(localization.contains("localizeTimes(document)"));
		assertFalse(report.contains("$("));
		assertTrue(report.contains("NodeFilter"));
	}

	@Test
	void rulesetsSeparateRuleScopesAndProvideAccessibleLocalFilters() throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/rules/rulesets.html");
		Document rulesets = Jsoup.parse(source);

		assertNotNull(rulesets.selectFirst(".wt-ruleset-actions"));
		assertNotNull(rulesets.selectFirst("[data-ruleset-region]"));
		assertNotNull(rulesets.selectFirst("[data-ruleset-loading][role=status]"));
		assertNotNull(rulesets.selectFirst("[data-rule-filter=module]"));
		assertNotNull(rulesets.selectFirst("[data-rule-filter=severity]"));
		// One table with All / Its own / Included tabs (UAT walkthrough, 2026-10-16).
		assertEquals(3, rulesets.select("nav.wt-segmented-filter [data-rule-scope]").size());
		assertEquals(0, rulesets.select("[data-rule-scope=effective]").size());
		assertFalse(source.contains("Effective rules"));
		assertFalse(source.contains("deduplicated rules"));
		assertEquals(rulesets.select("table").size(), rulesets.select("table > caption").size());
		assertEquals(rulesets.select("table").size(),
				rulesets.select(".wt-table-scroll > table").size());
		assertFalse(source.contains("datatable"));
		String rulesetScript = read(
				"watchtower-core/src/main/resources/static/scripts/rulesets.js");
		assertFalse(rulesetScript.contains("$("));
		assertTrue(rulesetScript.contains("region.setAttribute(\"aria-busy\", \"true\")"));
		for (org.jsoup.nodes.Element link : rulesets.select("a[target=_blank]")) {
			assertEquals("noopener noreferrer", link.attr("rel"));
		}
	}

	@Test
	void liveWorkloadShowsRecentValidationFailuresWithoutExpandingTheDashboard()
			throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/fragments/scanworkload.html");
		Document workload = Jsoup.parse(source);

		assertNotNull(workload.selectFirst(
				"[hx-get=/scan-workload][hx-trigger='every 10s']"
						+ "[hx-target='#pr-scan-workload'][hx-select='#pr-scan-workload']"));
		assertNotNull(workload.selectFirst(".wt-workload-failed"));
		assertNotNull(workload.selectFirst("details.wt-execution-skip-info summary[aria-label]"));
		assertTrue(source.contains("scanWorkload.validationFailed"));
		assertTrue(source.contains("item.reason"));
	}

	@Test
	void rulesetsPlaceActionsWithContextAndMaterializePaginatedFilters() throws IOException {
		Document rulesets = parse(
				"watchtower-core/src/main/resources/templates/rules/rulesets.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/rulesets.js");

		// The picker and the page's actions share one toolbar line, not a card.
		assertNotNull(rulesets.selectFirst(
				".wt-page-bar[data-ruleset-picker] .wt-ruleset-actions"));
		assertNotNull(rulesets.selectFirst(".wt-page-bar[data-ruleset-picker] #rulesetselect"));
		assertEquals(0, rulesets.select("[data-secrets-blocking-warning].alert").size(),
				"the secrets warning is a chip with a popover");
		org.jsoup.nodes.Element secrets = rulesets.selectFirst("[data-secrets-blocking-warning].wt-mini-chip");
		assertNotNull(secrets);
		assertTrue(secrets.attributes().toString().contains("data-tip="), "the explanation is the chip's hover text");
		assertEquals(0, rulesets.select("md-outlined-text-field[disabled]").size());
		// Seven buttons became New ruleset plus one More menu; filters are chip menus; rules are
		// paged on the server with the shared paginator, not hidden rows in the browser.
		assertEquals(1, rulesets.select(".wt-ruleset-actions md-filled-button").size());
		assertEquals(0, rulesets.select(".wt-ruleset-actions md-outlined-button").size());
		assertEquals(6, rulesets.select("[data-ruleset-more] .wt-menu-item").size());
		assertEquals(2, rulesets.select("details[data-rule-filter] > summary").size());
		assertTrue(rulesets.selectFirst("#results-region").html().contains("fragments/pagination :: pagination"));
		assertEquals(0, rulesets.select("nav[data-rule-pagination]").size());
		assertFalse(script.contains("RULE_PAGE_SIZE"));
		assertEquals(0, rulesets.select("[th\\:case][th\\:replace]").size(),
				"replacement fragments must not bypass their switch conditions");
	}

	@Test
	void ruleEditingUsesModuleTabsSearchAndSafeDeleteContent() throws IOException {
		Document editor = parse(
				"watchtower-core/src/main/resources/templates/rules/rule-edit.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/rule-edit.js");

		assertNotNull(editor.selectFirst("[role=tablist]"));
		assertNotNull(editor.selectFirst(
				"md-outlined-text-field[type=search][data-rule-search][label]"));
		assertEquals(2, editor.select("button[data-rule-kind-filter][aria-pressed]").size());
		// UAT walkthrough, 2026-10-16: module tabs with scanner icons, both kinds with their counts,
		// one row of outlined actions (Explain with the AI star) and a delete icon for custom rules.
		assertTrue(attrContains(editor, "[role=tab] .material-icons", "th:text", "scanner.icon()"));
		assertEquals(2, editor.select("button[data-rule-kind-filter] .wt-count-badge").size());
		assertEquals(0, editor.select(".wt-rule-actions a").size());
		assertTrue(editor.select(".wt-rule-actions md-outlined-button[has-icon]").size() >= 4);
		assertNotNull(editor.selectFirst(".wt-rule-actions .wt-ai-icon"));
		assertTrue(attrContains(editor,
				"button.wt-rule-delete[data-wt-dialog-target=#deleteRuleModal][aria-label]", "th:if", "isCustom()"));
		assertTrue(editor.select("[data-rule-link][data-rule-kind]").size() > 0);
		assertNotNull(editor.selectFirst("[data-rule-list]"));
		assertNotNull(editor.selectFirst("[data-rule-search-status][aria-live=polite]"));
		assertNotNull(editor.selectFirst("[data-rule-detail]"));
		assertFalse(script.contains("$("));
		assertFalse(script.contains("innerHTML"));
		assertTrue(script.contains("link.dataset.ruleKind === activeKind"));
	}

	@Test
	void ruleDesignersUseAConsistentAccessibleEditorWorkspace() throws IOException {
		Document wrapper = parse(
				"watchtower-core/src/main/resources/templates/rules/designer.html");
		String styles = read(
				"watchtower-core/src/main/resources/static/styles/components.css");
		assertNotNull(wrapper.selectFirst("[role=tablist][aria-label]"));
		assertTrue(wrapper.select("[role=tab][aria-selected]").size() > 0);
		// Each designer tab carries its scanner's icon and readable name (ScannerIdentity).
		assertTrue(attrContains(wrapper, "[role=tab] .material-icons", "th:text", "scanner.icon()"));
		assertTrue(attrContains(wrapper, "[role=tab] span", "th:text", "scanner.name()"));
		assertEquals(0, wrapper.select("[th\\:if][th\\:replace]").size());
		assertTrue(styles.contains(".wt-designer-page"));
		assertTrue(styles.contains(".wt-designer-workspace > .row"));
		assertTrue(styles.contains(".wt-designer-workspace > .row > .col-lg-6"));
		assertTrue(styles.contains(".wt-designer-workspace .cm-editor"));

		// Two cards (sample left, rule right) and one matches strip shared by every code designer
		// (UAT walkthrough, 2026-10-16): Run rule is the one filled button, Save rule beside it,
		// and the help is the rule card's "How to write it" chip.
		Document matches = parse("watchtower-core/src/main/resources/templates/fragments/designer.html");
		assertTrue(attrContains(matches, "[data-designer-output]", "th:fragment", "matches("));
		assertNotNull(matches.selectFirst("[data-designer-status][role=status][aria-live=polite]"));
		assertTrue(attrContains(matches, "button", "th:attr", "data-designer-match-line"));
		assertTrue(attrContains(matches, "[tabindex=0]", "th:fragment", "howto("));
		for (String template : RULE_DESIGNER_TEMPLATES) {
			String source = read(template);
			Document designer = Jsoup.parse(source);
			assertNotNull(designer.selectFirst("[data-rule-designer] .wt-designer-grid"), template);
			assertEquals(2, designer.select(".wt-designer-grid > [data-designer-editor]").size(), template);
			assertTrue(source.contains("~{fragments/designer :: matches(${matches}, ${error})}"), template);
			assertTrue(source.contains("~{fragments/designer :: howto("), template);
			assertNotNull(designer.selectFirst("form[data-designer-run-form]"), template);
			assertEquals(1, designer.select("[data-rule-designer] md-filled-button").size(), template);
			assertNotNull(designer.selectFirst("md-filled-button[data-run-rule][has-icon]"), template);
			assertNotNull(designer.selectFirst("md-outlined-button[data-save-rule][has-icon]"), template);
			assertEquals(0, designer.select("details.wt-designer-help").size(), template);
			assertFalse(source.contains("data-toggle=\"popover\""), template);
			assertFalse(source.contains("data-toggle=\"tooltip\""), template);
		}

		String interaction = read(
				"watchtower-core/src/main/resources/static/scripts/rule-designer.js");
		String pmdInteraction = read(
				"watchtower-module-pmd/src/main/resources/static/scripts/pmd-designer.js");
		assertFalse(interaction.contains("$("));
		assertTrue(interaction.contains("wtDesignerMatches"));
		assertTrue(pmdInteraction.contains("editor.setSize('100%', null)"));
		assertTrue(pmdInteraction.contains("wtDesignerMatches?.(editor)"));
		assertTrue(styles.contains(".wt-designer-grid"));
		assertTrue(styles.contains(".cm-line.wt-cm-hit"));
		assertTrue(interaction.contains("beforeunload"));
		assertTrue(interaction.contains("aria-busy"));
	}

	@Test
	void conditionalEmptyStatesNeverPlaceReplaceOnTheConditionalElement()
			throws IOException {
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/rules/designer.html",
				"watchtower-core/src/main/resources/templates/admin/encryption.html")) {
			Document page = parse(template);
			assertEquals(0, page.select("[th\\:if][th\\:replace], "
					+ "[th\\:unless][th\\:replace]").size(), template);
		}
	}

	@Test
	void advisoryDesignerUsesANativeBoundedTableWithoutDataTables() throws IOException {
		Document advisory = parse(
				"watchtower-module-advisory/src/main/resources/templates/designer/advisory.html");
		String script = read(
				"watchtower-module-advisory/src/main/resources/static/scripts/advisory-designer.js");

		assertNotNull(advisory.selectFirst("[data-rule-designer]"));
		assertNotNull(advisory.selectFirst(".wt-table-scroll > table > caption"));
		assertNotNull(advisory.selectFirst("tbody[data-advisory-rows]"));
		assertNotNull(advisory.selectFirst("[data-advisory-status][aria-live=polite]"));
		assertFalse(script.contains("$("));
		assertFalse(script.contains("DataTable"));
		assertFalse(script.contains("innerHTML"));
	}

	@Test
	void repositoryConfigurationUsesNativeFilteredTablesAndExplicitSaveActions()
			throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/configuration/repository.html");
		Document repositories = Jsoup.parse(source);

		// Integration tabs are server links (every integration, not only those on the current
		// page) and search is a GET form, so filtering covers all pages.
		assertNotNull(repositories.selectFirst("[role=tablist] a[role=tab][data-repository-tab]"));
		assertEquals(0, repositories.select("[data-repository-all]").size());
		assertEquals(0, repositories.select("[data-repository-panel]").size());
		assertNotNull(repositories.selectFirst("#results-region"));
		assertNotNull(repositories.selectFirst(
				"form[method=GET][role=search] md-outlined-text-field[type=search][name=q]"
						+ "[data-repository-search][label]"));
		assertNotNull(repositories.selectFirst("form[role=search] input[type=hidden][name=source]"));
		// Rulesets are chosen in the shared searchable picker (Special / Your rulesets / Scanner
		// rulesets), which posts rulesetId as the dropdown did.
		assertTrue(source.contains("fragments/rulesetpicker :: picker"));
		Document picker = parse("watchtower-core/src/main/resources/templates/fragments/rulesetpicker.html");
		assertNotNull(picker.selectFirst("input[type=hidden][name=rulesetId][data-ruleset-value]"));
		assertNotNull(picker.selectFirst("button[data-ruleset-toggle][aria-haspopup=listbox][aria-expanded=false]"));
		assertNotNull(picker.selectFirst("input[type=search][data-ruleset-search][aria-label]"));
		assertEquals(3, picker.select("[data-ruleset-group][role=group]").size());
		assertTrue(picker.select(".wt-picker-option[role=option]").size() >= 4);
		assertNotNull(repositories.selectFirst("[data-repository-filter-status][aria-live=polite]"));
		assertEquals(repositories.select("table").size(),
				repositories.select("table > caption").size());
		assertEquals(repositories.select("table").size(),
				repositories.select(".wt-table-scroll > table").size());
		assertTrue(repositories.select("[data-repository-status]").size() > 0);
		// Restraint: tabs sit directly on the page (no card around them, no description
		// paragraph); the row's Save is outlined - one filled button per row would shout.
		// The search pill filters as you type (Fixes board 2026-10-22): no Search button.
		assertNotNull(repositories.selectFirst("md-outlined-text-field.wt-search-pill[data-repository-search]"));
		assertEquals(0, repositories.select("form[data-filter-form] md-outlined-button[type=submit]").size());
		assertEquals(0, repositories.select("tbody md-filled-button").size());
		assertEquals(0, repositories.select(".wt-page-description").size());
		assertNull(repositories.selectFirst(".card [role=tablist]"));
		assertFalse(source.contains("Unavailable while disabled"));
		assertFalse(source.contains("datatable"));
		assertFalse(source.contains("onchange="));
		assertFalse(source.contains("reposwitcher.js"));
	}

	@Test
	void remainingVisibleFormControlsUseMaterialComponentsWhenAnEquivalentExists()
			throws IOException {
		Document logging = parse(
				"watchtower-core/src/main/resources/templates/admin/logging.html");
		Document role = parse(
				"watchtower-core/src/main/resources/templates/admin/roleedit.html");
		Document profile = parse(
				"watchtower-core/src/main/resources/templates/profile.html");
		Document checkov = parse(
				"watchtower-module-checkov/src/main/resources/templates/rule-edit/checkov-core.html");

		// Level filter is the one segmented control (UAT walkthrough, 2026-10-16).
		assertEquals(4, logging.select(".wt-segmented-filter[data-log-severity] [data-log-level-filter]").size());
		assertNotNull(logging.selectFirst(
				"md-outlined-text-field[type=search][data-log-filter][label]"));
		assertNotNull(logging.selectFirst("md-outlined-button[data-log-pause]"));
		assertNotNull(logging.selectFirst("button[data-log-refresh][aria-label]"));
		// One status line and one toolbar; no filled buttons, no separate Apply.
		assertEquals(0, logging.select("md-filled-button").size());
		assertEquals(0, logging.select("form[action=/logging]").size());
		assertNotNull(role.selectFirst(
				"md-outlined-text-field[type=search][data-privilege-search][label]"));
		assertEquals(2, profile.select(
				"md-outlined-text-field[readonly][data-api-credential]").size());
		// Read-only values are text, not read-only fields.
		assertEquals(3, checkov.select("td[data-checkov-definition]").size());
		assertEquals(0, checkov.select("md-outlined-text-field[readonly]").size());
	}

	@Test
	void dataTablesIsNotLoadedGlobally() throws IOException {
		String head = read(
				"watchtower-core/src/main/resources/templates/fragments/htmlhead.html");
		assertFalse(head.toLowerCase().contains("datatables"));
		assertFalse(head.contains("/scripts/datatable.js"));
	}

	@Test
	void applicationShellAndRouteHelpersDoNotRequireJquery() throws IOException {
		String head = read(
				"watchtower-core/src/main/resources/templates/fragments/htmlhead.html");
		String pom = read("watchtower-core/pom.xml");
		assertFalse(head.contains("/webjars/jquery"));
		assertFalse(pom.contains("<artifactId>jquery</artifactId>"));

		for (String script : List.of(
				"watchtower-core/src/main/resources/static/scripts/auto-dismiss-alerts.js",
				"watchtower-module-eslint/src/main/resources/static/scripts/eslint-designer.js",
				"watchtower-module-eslint/src/main/resources/static/scripts/eslint-editor.js",
				"watchtower-module-json/src/main/resources/static/scripts/json-designer.js",
				"watchtower-module-pmd/src/main/resources/static/scripts/pmd-designer.js",
				"watchtower-module-regex/src/main/resources/static/scripts/regex-designer.js")) {
			assertFalse(read(script).contains("$("), script);
		}
	}

	@Test
	void apiIntegrationsUseSecretSafeFieldsStatusAndConsistentActions() throws IOException {
		String source = read(
				"watchtower-core/src/main/resources/templates/configuration/apisettings.html");
		Document integrations = Jsoup.parse(source);

		assertNotNull(integrations.selectFirst("table > caption"));
		assertNotNull(integrations.selectFirst(".wt-table-scroll > table"));
		assertNotNull(integrations.selectFirst("[data-connection-result][role=status]"));
		assertTrue(integrations.select("form[action=/apisettings/testConnection]").size() > 0);
		assertTrue(integrations.select("[data-wt-dialog-target=#deleteModal]").size() > 0);
		// Restraint: the label opens the integration; Test and Delete are quiet row actions;
		// no header paragraph; an untested row says nothing.
		assertTrue(integrations.select("tbody th a").stream()
				.anyMatch(a -> a.attr("th:href").contains("/apisettings/configure")));
		assertNotNull(integrations.selectFirst(
				"button.wt-icon-action--danger[data-wt-dialog-target=#deleteModal][data-tip]"));
		// Connection and webhook are chips with their meaning on hover; adding is one menu.
		assertNotNull(integrations.selectFirst("[data-connection-chip][tabindex=0]"));
		assertNotNull(integrations.selectFirst("[data-webhook-chip]"));
		assertNotNull(integrations.selectFirst("details[data-add-integration] a.wt-menu-item"));
		assertEquals(0, integrations.select("md-outlined-select[name=apiType]").size());
		assertEquals(0, integrations.select("tbody md-filled-button").size());
		assertEquals(0, integrations.select(".card-header p").size());
		assertFalse(source.contains("Not tested this session"));

		// Delete opens the shared type-to-confirm dialog; Unregister asks first in place.
		Document configurePage = parse(
				"watchtower-core/src/main/resources/templates/configuration/apiconfigure.html");
		assertNotNull(configurePage.selectFirst("[data-wt-dialog-target=#deleteModal]"));
		Document deletion = parse("watchtower-core/src/main/resources/templates/configuration/deleteintegration.html");
		assertNotNull(deletion.selectFirst("form[action=/apisettings/delete] [name=confirmName][required]"));
		assertNotNull(deletion.selectFirst("md-filled-button[data-wt-confirm-submit][disabled]"));
		assertNotNull(configurePage.selectFirst("form[action=/apisettings/unregister][data-confirm-action]"));
		assertEquals(1, configurePage.select("md-filled-button").size(),
				"one primary action on the configure page");
		assertTrue(read("watchtower-core/src/main/resources/templates/fragments/htmlhead.html")
				.contains("/scripts/confirm-action.js"));

		// Stored secrets: a "Saved" chip with Replace, the field only after Replace, never the value.
		String secretSource = read(
				"watchtower-core/src/main/resources/templates/configuration/secretfield.html");
		Document secret = Jsoup.parse(secretSource);
		assertNotNull(secret.selectFirst("md-outlined-text-field[type=password][autocomplete=new-password]"));
		assertNotNull(secret.selectFirst("button[data-secret-replace]"));
		assertFalse(secretSource.contains("th:value"));
		assertTrue(secretSource.contains("leave unchanged"));
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/configuration/bbcloudconfigure.html",
				"watchtower-core/src/main/resources/templates/configuration/ecrconfigure.html")) {
			String configureSource = read(template);
			Document configure = Jsoup.parse(configureSource);
			assertTrue(configureSource.contains("configuration/secretfield :: field("), template);
			assertFalse(configureSource.contains("th:value=\"${entity?.webhookSecret}\""), template);
			assertFalse(configureSource.contains("th:value=\"${entity?.auth}\""), template);
			assertFalse(configureSource.contains("th:value=\"${entity?.awsSecretKey}\""), template);
			// What happens when a scan blocks: choice chips; setup steps behind one button.
			assertNotNull(configure.selectFirst("fieldset.wt-choice-chips input[type=radio][name=rejectOption]"), template);
			assertNotNull(configure.selectFirst("details[data-setup-guide] > summary"), template);
			assertEquals(0, configure.select("md-outlined-select[name=rejectOption]").size(), template);
		}
	}

	@Test
	void prSettingsUseOneGuidedFormWithServerSideBounds() throws IOException {
		Document settings = parse(
				"watchtower-core/src/main/resources/templates/configuration/prsettings.html");

		assertEquals(1, settings.select("form[data-pr-settings-form]").size());
		assertEquals(3, settings.select("form[data-pr-settings-form] [type=number][required]").size());
		assertEquals(1, settings.select("form[data-pr-settings-form] md-filled-button[type=submit]").size());
		assertEquals(3, settings.select("form[data-pr-settings-form] [aria-describedby]").size());
		assertEquals(0, settings.select("table").size());
		assertNotNull(settings.selectFirst("[data-pr-settings-readonly]"));
		// Restraint: one card, no explanation card, view-only as a chip, no header paragraph.
		assertEquals(0, settings.select("details.card").size());
		assertEquals(0, settings.select(".card-header p").size());
		assertNotNull(settings.selectFirst("[data-pr-settings-readonly] .wt-status-chip"));
	}

	@Test
	void profileSeparatesAccountKeysAndPasswordWithOneTimeSecretDialog() throws IOException {
		String source = read("watchtower-core/src/main/resources/templates/profile.html");
		Document profile = Jsoup.parse(source);

		assertNotNull(profile.selectFirst("[data-profile-section=account]"));
		assertNotNull(profile.selectFirst("[data-profile-section=api-keys] table > caption"));
		assertNotNull(profile.selectFirst("[data-profile-section=password]"));
		assertNotNull(profile.selectFirst("[name=currentPassword][autocomplete=current-password]"));
		assertEquals(2, profile.select("[autocomplete=new-password]").size());
		assertNotNull(profile.selectFirst("[data-new-api-key-dialog]"));
		assertNotNull(profile.selectFirst("[data-copy-api-secret]"));
		assertNotNull(profile.selectFirst("[data-copy-status][aria-live=polite]"));
		// Restraint: the account is the page header (initial, name, role chips, Since chip), not
		// a card; Change password is a header button that opens a dialog (UAT walkthrough,
		// 2026-10-16); key delete is a quiet red icon; no keys is an empty state; one filled
		// button on the page (dialogs aside).
		assertNull(profile.selectFirst(".card[data-profile-section=account]"));
		assertNotNull(profile.selectFirst("[data-profile-section=account] .wt-avatar"));
		assertNotNull(profile.selectFirst("[data-profile-section=account] [data-wt-dialog-open=#passwordModal]"));
		assertNotNull(profile.selectFirst("md-dialog#passwordModal[data-profile-section=password]"));
		assertNull(profile.selectFirst("details[data-profile-section=password]"));
		assertNotNull(profile.selectFirst(
				"button.wt-icon-danger[data-wt-dialog-target=#deleteModal]"));
		assertNotNull(profile.selectFirst("[data-api-keys-empty][th:if=${apiKeys.empty}]"));
		assertEquals(1, profile.select("md-filled-button:not(md-dialog md-filled-button)").size());
		assertEquals(0, profile.select(".card-header p").size());
		assertFalse(read("watchtower-core/src/main/resources/static/scripts/profile.js")
				.contains("$("));
	}

	@Test
	void userAndRoleAdministrationUseSharedTablesAndNamedConfirmations() throws IOException {
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/admin/usermgmt.html",
				"watchtower-core/src/main/resources/templates/admin/rolemgmt.html")) {
			Document page = parse(template);
			assertEquals(page.select("table").size(), page.select("table > caption").size(), template);
			assertEquals(page.select("table").size(),
					page.select(".wt-table-scroll > table").size(), template);
			assertNotNull(page.selectFirst("[data-wt-dialog-target][data-name]"), template);
			// Restraint: the name opens the record; delete is a quiet danger row action that
			// confirms; no header paragraph restating the page title.
			assertTrue(page.select("tbody th a").stream().anyMatch(a -> a.hasAttr("th:href")),
					template);
			// One quiet red delete icon per row that confirms (UAT walkthrough, 2026-10-16).
			assertNotNull(page.selectFirst(
					"button.wt-copy-button.wt-icon-danger[data-wt-dialog-target=#myModal][data-tip]"),
					template);
			assertEquals(0, page.select("tbody md-outlined-button, tbody md-filled-button").size(), template);
			assertEquals(0, page.select(".card-header p").size(), template);
		}
		Document users = parse("watchtower-core/src/main/resources/templates/admin/usermgmt.html");
		// Your own row says "You" instead of offering Delete; roles are chips; last login is
		// relative with the full time on hover.
		assertTrue(users.selectFirst("button.wt-icon-danger").attr("th:if").contains("!isYou"));
		assertNotNull(users.selectFirst("span.wt-mini-chip[th:if=${isYou}]"));
		assertNotNull(users.selectFirst("[th:each=role : ${user.roles}].wt-mini-chip"));
		assertNotNull(users.selectFirst(".localizetime[data-time-style=relative]"));
		Document roles = parse("watchtower-core/src/main/resources/templates/admin/rolemgmt.html");
		// The default role is a star on the row and shows "In use" instead of Delete.
		assertNotNull(roles.selectFirst("form[action=/rolemgmt/default] button[data-make-default]"));
		assertNull(roles.selectFirst("#defaultRoleModal"));
		assertTrue(roles.selectFirst("button.wt-icon-danger").attr("th:if").contains("!role.isDefaultRole()"));
		assertNotNull(roles.selectFirst("[data-role-users]"));
		assertNotNull(roles.selectFirst(".wt-meter"));
		assertFalse(read("watchtower-core/src/main/resources/static/scripts/modal-delete-user.js")
				.contains("$("));
		assertFalse(read("watchtower-core/src/main/resources/static/scripts/rolemgmt.js")
				.contains("$("));
	}

	@Test
	void roleEditingGroupsSearchesAndBulkSelectsPrivileges() throws IOException {
		Document editor = parse("watchtower-core/src/main/resources/templates/admin/roleedit.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/role-privileges.js");

		assertNotNull(editor.selectFirst(
				"md-outlined-text-field[type=search][data-privilege-search]"));
		assertNotNull(editor.selectFirst("[data-privilege-status][aria-live=polite]"));
		assertNotNull(editor.selectFirst("[data-privilege-group]"));
		// One Select all / Clear all toggle per group, not two buttons.
		assertNotNull(editor.selectFirst("[data-toggle-group]"));
		assertEquals(0, editor.select("[data-select-group], [data-clear-group]").size());
		// Read-only viewers see what is granted as text, never disabled checkboxes.
		assertNotNull(editor.selectFirst("[data-granted-privileges]"));
		assertEquals(0, editor.select("md-checkbox[th:disabled]").size());
		assertFalse(script.contains("$("));
		assertFalse(script.contains("innerHTML"));
	}

	@Test
	void encryptionLabelsKeyLifecycleAndUsesNamedRotationConfirmations() throws IOException {
		String source = read("watchtower-core/src/main/resources/templates/admin/encryption.html");
		Document encryption = Jsoup.parse(source);

		assertNotNull(encryption.selectFirst("[data-encryption-schedule]"));
		assertNotNull(encryption.selectFirst("[data-key-status]"));
		assertNotNull(encryption.selectFirst("[data-next-rotation]"));
		assertEquals(encryption.select("table").size(), encryption.select("table > caption").size());
		assertEquals(encryption.select("table").size(),
				encryption.select(".wt-table-scroll > table").size());
		assertNotNull(encryption.selectFirst("[data-wt-dialog-target=#rotateKeyModal][data-name]"));
		// Restraint: the schedule and key status are one line; the schedule form is a dialog;
		// no page-level filled buttons; a rotating key has no Rotate button rather than a
		// disabled one.
		assertNotNull(encryption.selectFirst(".wt-page-bar [data-wt-dialog-target=#scheduleModal]"));
		// The mode is a chip by the title; an empty key list is an empty state with no pager.
		assertNotNull(encryption.selectFirst(".wt-page-bar [data-encryption-mode]"));
		assertNotNull(encryption.selectFirst("[data-encryption-empty][th:if=${deks.empty}]"));
		assertNotNull(encryption.selectFirst("section[th:unless=${deks.empty}] [th:replace*=pagination]"));
		assertFalse(source.contains("Key-encryption key last rotated"));
		assertNotNull(encryption.selectFirst("md-dialog#scheduleModal form[action=/encryption/rotate/schedule]"));
		assertEquals(0, encryption.select("md-filled-button:not(md-dialog md-filled-button)").size());
		assertFalse(source.contains("th:disabled=\"${dek.rotationInProgress}\""));
		assertEquals(0, encryption.select(".card-header p").size());
		assertFalse(source.contains("currentKey"));
		assertFalse(source.contains("previousKey"));
		String script = read("watchtower-core/src/main/resources/static/scripts/encryption.js");
		assertFalse(script.contains("$("));
		assertFalse(script.contains("innerHTML"));
	}

	@Test
	void errorPageUsesSafeBrandedStateAndRecoveryActions() throws IOException {
		String source = read("watchtower-core/src/main/resources/templates/error.html");
		Document error = Jsoup.parse(source);

		assertNotNull(error.selectFirst("main"));
		assertEquals(1, error.select("h1").size());
		assertNotNull(error.selectFirst("[data-request-id]"));
		assertNotNull(error.selectFirst("[data-error-home]"));
		assertNotNull(error.selectFirst("[data-error-back]"));
		assertNotNull(error.selectFirst("[data-error-retry]"));
		assertFalse(source.contains("${message}"));
		assertFalse(source.contains("${trace}"));
		assertFalse(source.contains("${exception}"));
	}

	@Test
	void loggingUsesBoundedRefreshableAndLocallyFilteredOutput() throws IOException {
		Document logging = parse(
				"watchtower-core/src/main/resources/templates/admin/logging.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/logging.js");

		assertNotNull(logging.selectFirst("[data-log-filter][type=search]"));
		assertNotNull(logging.selectFirst("[data-log-severity]"));
		assertNotNull(logging.selectFirst("[data-log-pause][aria-pressed]"));
		assertNotNull(logging.selectFirst("[data-log-status][role=status][aria-live=polite]"));
		assertNotNull(logging.selectFirst("[data-log-region] [data-log-lines]"));
		assertNotNull(logging.selectFirst("[data-log-line]"));
		assertFalse(script.contains("$("));
		assertTrue(script.contains("setInterval"));
		assertTrue(script.contains("scrollTop"));
	}

	@Test
	void browserRegressionHarnessCoversAccessibilityViewportsAndPerformance() throws IOException {
		String packageJson = read(
				"watchtower-core/src/main/frontend/material-web/package.json");
		String config = read(
				"watchtower-core/src/main/frontend/material-web/playwright.config.js");
		String routes = read(
				"watchtower-core/src/main/frontend/material-web/e2e/routes.spec.js");
		String support = read(
				"watchtower-core/src/main/frontend/material-web/e2e/support.js");
		String workflow = read(".github/workflows/browser-qa.yml");

		assertTrue(packageJson.contains("@playwright/test"));
		assertTrue(packageJson.contains("@axe-core/playwright"));
		assertTrue(config.contains("width: 1440"));
		assertTrue(config.contains("width: 768"));
		assertTrue(config.contains("width: 375"));
		assertTrue(config.contains("maxDiffPixels: 5"));
		assertTrue(routes.contains("assertNoSeriousAxeViolations"));
		assertTrue(routes.contains("assertPerformanceGates"));
		assertTrue(support.contains("'/admin/ui/components'"));
		assertTrue(workflow.contains("workflow_dispatch"));
		assertTrue(workflow.contains("npx playwright install --with-deps chromium"));
	}

	@Test
	void templatesDoNotUseStylingHeadingsAndEveryTableHasACaption() throws IOException {
		for (Path template : TemplateModuleScanner.findAllTemplateFiles()) {
			Document document = Jsoup.parse(Files.readString(template));
			assertEquals(0, document.select("h5, h6").size(), template.toString());
			assertEquals(document.select("table").size(),
					document.select("table > caption").size(), template.toString());
		}
	}

	@Test
	void findingWorkspaceProvidesCopyActionsAndBoundedClientPagination() throws IOException {
		Document findings = parse(
				"watchtower-core/src/main/resources/templates/fragments/findings.html");
		String script = read(
				"watchtower-core/src/main/resources/static/scripts/finding-workspace.js");
		String styles = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		assertNotNull(findings.selectFirst("[data-copy-finding=title]"));
		assertNotNull(findings.selectFirst("[data-copy-finding=location]"));
		assertNotNull(findings.selectFirst("[data-copy-finding=vector]"));
		assertNotNull(findings.selectFirst("[data-copy-status][role=status][aria-live=polite]"));
		assertNotNull(findings.selectFirst("[data-finding-list-viewport]"));
		assertNotNull(findings.selectFirst("nav[data-finding-pagination][aria-label]"));
		assertNotNull(findings.selectFirst("[data-finding-range][role=status][aria-live=polite]"));
		assertNotNull(findings.selectFirst("button[data-finding-previous]"));
		assertNotNull(findings.selectFirst("button[data-finding-next]"));
		assertTrue(script.contains("navigator.clipboard.writeText"));
		assertTrue(script.contains("PAGE_SIZE = 10"));
		assertFalse(script.contains("innerHTML"));
		assertTrue(styles.contains("content-visibility: auto"));
		assertTrue(styles.contains(".wt-finding-list"));
		// The list/detail split: a resizable list column, the resizer, and the detail.
		assertTrue(styles.contains(
				"grid-template-columns: minmax(18rem, var(--wt-split-percent, 34%)) 0.75rem minmax(20rem, 1fr)"));
		assertTrue(styles.contains(".wt-finding-list-viewport"));
		assertTrue(styles.contains("overflow-y: auto"));
		assertTrue(styles.contains(".wt-finding-detail {"));
		assertTrue(styles.contains("block-size: var(--wt-findings-workspace-height)"));
	}

	@Test
	void findingWorkspaceUsesMaterialFiltersAndAReportFirstDetailLayout() throws IOException {
		Document findings = parse(
				"watchtower-core/src/main/resources/templates/fragments/findings.html");
		String styles = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		assertNotNull(findings.selectFirst(
				"md-outlined-text-field[data-finding-search][type=search][label]"));
		// Severity is a coloured bar with one chip per severity (UAT walkthrough, 2026-10-15); the
		// chips set the same hidden filter value, and the location filter stays a Material select.
		assertNotNull(findings.selectFirst("input[type=hidden][data-finding-severity]"));
		assertNotNull(findings.selectFirst(".wt-severity-chips button[aria-pressed]"));
		// The file filter is one chip menu with a count over a hidden value (UAT walkthrough,
		// 2026-10-16), and the engine's own wording is a chip, not a fold.
		assertNotNull(findings.selectFirst("details[data-finding-location-menu] > summary [data-finding-location-count]"));
		assertNotNull(findings.selectFirst("input[type=hidden][data-finding-location]"));
		assertNotNull(findings.selectFirst(".wt-finding-detail-heading [data-original-message][tabindex=0]"));
		assertEquals(0, findings.select("details[data-original-message]").size());
		assertEquals("34", findings.selectFirst("[data-split-workspace]")
				.attr("data-split-default"));
		assertEquals("findings-v2", findings.selectFirst("[data-split-workspace]")
				.attr("data-split-key"));
		assertEquals("34", findings.selectFirst("[data-workspace-resizer]")
				.attr("aria-valuenow"));
		assertTrue(styles.contains("var(--wt-split-percent, 34%)"));
		assertTrue(styles.contains(".wt-finding-detail > .wt-metadata-grid > div:first-child"));
		// Long details and opened source scroll inside the pane instead of being cut off (user, 2026-10-22).
		assertTrue(styles.contains("overflow-y: auto;\n  overscroll-behavior: contain;"));
	}

	@Test
	void scanSummariesUseFriendlyTargetsAndCompactSeverityCountsEverywhere()
			throws IOException {
		String severity = read(
				"watchtower-core/src/main/resources/templates/fragments/severity.html");
		String dashboard = read(
				"watchtower-core/src/main/resources/templates/fragments/dashboard.html");
		String home = read(
				"watchtower-core/src/main/resources/templates/metricsdashboard.html");
		String styles = read(
				"watchtower-core/src/main/resources/static/styles/components.css");

		assertTrue(severity.contains("fragment=\"compactSummary(violations)\""));
		assertTrue(severity.contains("fragment=\"entitySummary(violations)\""));
		assertTrue(severity.contains("fragment=\"countSummary(counts)\""));
		assertTrue(severity.contains("data-findings-total"));
		assertTrue(severity.contains("aria-label"));
		// Home and the scan dashboards share one activity table (fragments/scanactivity).
		assertTrue(dashboard.contains("fragments/scanactivity :: table("));
		assertTrue(home.contains("fragments/scanactivity :: table("));
		assertTrue(read("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.contains("severity :: countSummary(${activity.severityCounts})"));

		assertTrue(read(PR_RESULTS).contains("fragments/scanactivity :: table("));
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/upload_scan/results.html",
				"watchtower-core/src/main/resources/templates/image_scan/results.html",
				"watchtower-core/src/main/resources/templates/pull_requests/mcrs.html")) {
			assertTrue(read(template).contains("severity :: compactSummary("), template);
		}
		// Upload and image reports count findings in the workspace, not again in the facts.
		String image = read("watchtower-core/src/main/resources/templates/image_scan/scanreport.html");
		Document imageReport = Jsoup.parse(image);
		assertFalse(image.contains("<dt>Findings</dt>"));
		// The image report has the same header: status chip by the title, registry/time/duration
		// chips instead of the five-field grid, and the shared Scanners row.
		assertEquals(0, imageReport.select(".card, dl.wt-metadata-grid").size());
		assertNotNull(imageReport.selectFirst(".wt-report-head .wt-report-head__status"));
		assertTrue(image.contains("fragments/scanstrip :: scanners(${result.scannerTiles}, ${result.executionSummary})"));
		assertFalse(image.contains("Execution"));
		// The upload report has the pull request report's header: status chip by the title, fact
		// chips (ticket copies on click), the shared Scanners row, and a plain-words failure card.
		String upload = read("watchtower-core/src/main/resources/templates/upload_scan/scanreport.html");
		Document uploadReport = Jsoup.parse(upload);
		assertFalse(upload.contains("<dt>Findings</dt>"));
		assertEquals(0, uploadReport.select(".card, dl.wt-metadata-grid").size());
		assertNotNull(uploadReport.selectFirst(".wt-report-head .wt-report-head__status"));
		assertNotNull(uploadReport.selectFirst("button.wt-copy-chip[th:attr*=data-copy-text]"));
		assertTrue(upload.contains("fragments/scanstrip :: scanners("));
		assertNotNull(uploadReport.selectFirst(".wt-failure-card[role=alert] details > summary"));
		assertTrue(read("watchtower-core/src/main/resources/templates/pull_requests/scanreport.html")
				.contains("fragments/scanstrip :: scanners("), "one Scanners row for both reports");
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/pull_requests/submitscan.html",
				"watchtower-core/src/main/resources/templates/upload_scan/submitscan.html")) {
			// Recent scans use Home's shared table (count + severity chips + MCR chip).
			assertTrue(read(template).contains("fragments/scanactivity :: table(${recentActivity}"), template);
		}
		assertTrue(read("watchtower-core/src/main/resources/templates/fragments/scanactivity.html")
				.contains("wt-scan-target"));
		assertTrue(styles.contains(".wt-scan-target"));
		assertTrue(styles.contains("font-weight: 500"));
	}

	@Test
	void everyScanReportShowsRecordedRulesAndScannerExecution() throws IOException {
		String fragment = read(
				"watchtower-core/src/main/resources/templates/fragments/scanexecution.html");
		String performance = read(
				"watchtower-core/src/main/resources/templates/fragments/prscanperformance.html");
		assertTrue(fragment.contains("Rules selected"));
		assertTrue(fragment.contains("Scanners ran"));
		assertTrue(fragment.contains("Scanners skipped"));
		assertTrue(fragment.contains("scanner.reason"));
		assertTrue(fragment.contains("result.formatDuration(scanner.durationMs)"));
		assertTrue(performance.contains("fragments/scanexecution :: performance"));

		assertTrue(read("watchtower-core/src/main/resources/templates/image_scan/scanreport.html")
				.contains("fragments/scanstrip :: scanners("));
		// The upload report shows its executions as the shared scanner tiles (state and time on
		// hover, skipped scanners in "+N"), like the pull request report.
		assertTrue(read("watchtower-core/src/main/resources/templates/upload_scan/scanreport.html")
				.contains("fragments/scanstrip :: scanners(${result.scannerTiles}, ${result.executionSummary})"));
		for (String template : List.of(
				"watchtower-core/src/main/resources/templates/pull_requests/scanreport.html",
				"watchtower-core/src/main/resources/templates/pull_requests/mcrreport.html")) {
			String source = read(template);
			assertFalse(source.contains("fragments/scanexecution :: compact"), template);
			assertFalse(source.contains("fragments/scanexecution :: summary"), template);
		}
		String pullRequestReport = read(
				"watchtower-core/src/main/resources/templates/pull_requests/scanreport.html");
		assertFalse(pullRequestReport.contains("<dt>Findings</dt>"));
		String mcrReport = read(
				"watchtower-core/src/main/resources/templates/pull_requests/mcrreport.html");
		assertFalse(mcrReport.contains("<dt>MCR findings</dt>"));
	}

	/** Whether an element matching {@code css} has {@code attribute} containing {@code text}. */
	private static boolean attrContains(Document document, String css, String attribute, String text) {
		return document.select(css).stream().anyMatch(element -> element.attr(attribute).contains(text));
	}

	private static Document parse(String relativePath) throws IOException {
		return Jsoup.parse(read(relativePath));
	}

	@Test
	void theBitbucketWebhookSecretIsAChipWithARotateLinkAndNeverAnInput() throws IOException {
		String source = read("watchtower-core/src/main/resources/templates/configuration/bbcloudconfigure.html");
		Document page = Jsoup.parse(source);
		assertNull(page.selectFirst("[name=webhookSecret], #webhookSecret"), "the secret is Watchtower's: it is never typed");
		assertTrue(source.contains("Managed by Watchtower"));
		assertTrue(source.contains("Set when the webhook is registered"));
		var rotate = page.selectFirst("a.wt-icon-action[aria-label=Rotate the signing secret]");
		assertNotNull(rotate);
		assertTrue(rotate.attr("th:href").contains("/webhooks/manage"));
	}

	/**
	 * The page is boosted by htmx, which reads a form's action once, when the page loads. A form
	 * whose action a script changes later (a shared delete or edit dialog) would keep posting to
	 * its first action: deleting an alert channel posted to the route endpoint and deleting a rule
	 * posted to the page itself. Such forms submit natively.
	 */
	@Test
	void formsWhoseActionIsSetByAScriptAreNotBoostedByHtmx() throws IOException {
		var forms = java.util.Map.of(
				"watchtower-core/src/main/resources/templates/configuration/alertsettings.html",
				List.of("routeForm", "channelForm", "confirmDeleteForm"),
				"watchtower-core/src/main/resources/templates/rules/rule-edit.html",
				List.of("deleteModalForm"),
				"watchtower-core/src/main/resources/templates/configuration/repositoryedit.html",
				List.of("repoEditForm"),
				"watchtower-module-aws-security-agent/src/main/resources/templates/awssecurity/readiness.html",
				List.of("aws-delete-review-form"));
		for (var template : forms.entrySet()) {
			Document page = Jsoup.parse(read(template.getKey()));
			for (String id : template.getValue()) {
				var form = page.getElementById(id);
				assertNotNull(form, id + " is missing from " + template.getKey());
				assertEquals("false", form.attr("hx-boost"), id + " must not be boosted by htmx");
			}
		}
	}

	private static String read(String relativePath) throws IOException {
		Path path = TemplateModuleScanner.repoRoot().resolve(relativePath);
		return Files.readString(path);
	}
}

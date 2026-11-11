package com.tracelink.appsec.watchtower.core.sidebar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;

public class SidebarServiceTest {

	private final SidebarService sidebarService = new SidebarService();

	@ParameterizedTest
	@CsvSource({
			"/, Home",
			"/scan/dashboard, Pull Requests",
			"/scan/results, Pull Requests",
			"/scan/results/all, Pull Requests",
			"/scan/mcr, Pull Requests",
			"/scan/mcr/report/5, Pull Requests",
			"/scan/report/5, Pull Requests",
			"/uploadscan, Upload Scans",
			"/uploadscan/results, Upload Scans",
			"/uploadscan/report/5, Upload Scans",
			"/reposcan/dashboard, Repository Scans",
			"/reposcan, Repository Scans",
			"/reposcan/run/3/1, Repository Scans",
			"/reposcan/report/7, Repository Scans",
			"/repository/pull_request, Repository Scans",
			"/repository/pull_request/5, Repository Scans",
			"/imagescan/dashboard, Image Scans",
			"/imagescan/results, Image Scans",
			"/rulesets, Rules",
			"/designer, Rules",
			"/rule/edit, Rules",
			"/apisettings, Configuration",
			"/apisettings/configure, Configuration",
			"/logging, Administration",
			"/encryption, Administration",
			"/usermgmt, Administration",
			"/usermgmt/edit/5, Administration",
			"/rolemgmt, Administration",
			"/rolemgmt/edit/5, Administration"
	})
	public void testGetGroupNameForPathResolvesViaLongestPrefix(String path, String expectedGroup) {
		assertEquals(expectedGroup, sidebarService.getGroupNameForPath(path).orElse(null));
	}

	@Test
	public void testGetGroupNameForPathFallsBackToFirstSegmentWhenNoLinkIsAPrefix() {
		// No Image Scans link is itself a path-prefix of a report-detail URL (only
		// /imagescan/dashboard and /imagescan/results exist), so this only resolves via the
		// first-path-segment fallback tier, not the longest-prefix tier.
		assertEquals("Image Scans", sidebarService.getGroupNameForPath("/imagescan/report/5").orElse(null));
	}

	@Test
	public void testModuleCanAddALinkToAnExistingGroup() {
		SidebarLink link = new SidebarLink().setDisplayName("Secrets Allowlist")
				.setUrl("/betterleaks/allowlist").setMaterialIcon("rule")
				.setAuthorizationExpression("hasAuthority('Betterleaks Allowlist Modify')");

		sidebarService.addLink("Configuration", link);

		SidebarMenuGroup configuration = sidebarService.getMenuGroups().stream()
				.filter(group -> group.getGroupName().equals("Configuration")).findFirst()
				.orElseThrow();
		assertEquals(link, configuration.getLinks().get(configuration.getLinks().size() - 1));
		assertEquals("Configuration",
				sidebarService.getGroupNameForPath("/betterleaks/allowlist").orElse(null));
	}

	@Test
	public void testAddingALinkTwiceKeepsOneCopy() {
		SidebarLink link = new SidebarLink().setDisplayName("Secrets Allowlist")
				.setUrl("/betterleaks/allowlist");
		int before = sidebarService.getMenuGroups().stream()
				.filter(group -> group.getGroupName().equals("Configuration")).findFirst()
				.orElseThrow().getLinks().size();

		sidebarService.addLink("Configuration", link);
		sidebarService.addLink("Configuration",
				new SidebarLink().setDisplayName("Again").setUrl("/betterleaks/allowlist"));

		assertEquals(before + 1, sidebarService.getMenuGroups().stream()
				.filter(group -> group.getGroupName().equals("Configuration")).findFirst()
				.orElseThrow().getLinks().size());
	}

	@Test
	public void testAddingALinkToAnUnknownGroupFails() {
		org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
				() -> sidebarService.addLink("No Such Group", new SidebarLink().setUrl("/x")));
	}

	@Test
	public void testGetGroupNameForPathReturnsEmptyWhenNoSidebarLinkSharesAFirstSegment() {
		assertTrue(sidebarService.getGroupNameForPath("/profile").isEmpty());
	}

	@Test
	public void testGetGroupNameForPathNeverMatchesAnExternalLink() {
		// "DB Console" is an external link (/console) - it must never be reported as the
		// resolved section for a path that happens to share its literal URL, since it is not a
		// real Watchtower page this app renders its own breadcrumb on.
		assertTrue(sidebarService.getGroupNameForPath("/console").isEmpty());
	}

	@Test
	void buildsClickableBreadcrumbsForResultAndReportRoutes() {
		assertIterableEquals(List.of(
				new BreadcrumbLink("Pull Requests", "/scan/results/all"),
				new BreadcrumbLink("Results", "/scan/results/all")),
				sidebarService.getBreadcrumbLinksForPath("/scan/results/all"));
		assertIterableEquals(List.of(
				new BreadcrumbLink("Pull Requests", "/scan/results/all"),
				new BreadcrumbLink("Results", "/scan/results/all")),
				sidebarService.getBreadcrumbLinksForPath("/scan/report/158700"));
		assertIterableEquals(List.of(
				new BreadcrumbLink("Pull Requests", "/scan/mcr"),
				new BreadcrumbLink("MCR", "/scan/mcr")),
				sidebarService.getBreadcrumbLinksForPath("/scan/mcr/report/42"));
	}

	@Test
	void assistantSubPagesLeadBackToAssistantSettings() {
		assertIterableEquals(List.of(new BreadcrumbLink("AI assistant settings", "/admin/assistant")),
				sidebarService.getBreadcrumbLinksForPath("/admin/assistant/evaluation"));
		assertIterableEquals(List.of(new BreadcrumbLink("AI assistant settings", "/admin/assistant")),
				sidebarService.getBreadcrumbLinksForPath("/admin/assistant/transcripts/abc"));
	}

	@Test
	void buildsClickableBreadcrumbsForOtherDetailRoutesAndProfile() {
		assertIterableEquals(List.of(
				new BreadcrumbLink("Upload Scans", "/uploadscan/results/all"),
				new BreadcrumbLink("Results", "/uploadscan/results/all")),
				sidebarService.getBreadcrumbLinksForPath("/uploadscan/report/TICKET-1"));
		assertIterableEquals(List.of(
				new BreadcrumbLink("Image Scans", "/imagescan/results/all"),
				new BreadcrumbLink("Results", "/imagescan/results/all")),
				sidebarService.getBreadcrumbLinksForPath("/imagescan/report/9"));
		assertIterableEquals(List.of(new BreadcrumbLink("Home", "/")),
				sidebarService.getBreadcrumbLinksForPath("/profile"));
	}

	@Test
	void usesCompactDeveloperFacingNavigationLabels() {
		List<String> labels = sidebarService.getMenuGroups().stream()
				.flatMap(group -> group.getLinks().stream())
				.map(SidebarLink::getDisplayName)
				.filter(label -> label != null)
				.toList();

		assertIterableEquals(List.of("Dashboard", "New Scan", "Results", "MCR", "Bypasses",
				"Dashboard", "New Scan", "Results", "Dashboard", "Repositories", "Results",
				"Dashboard", "Results",
				"Rule Work", "Knowledge", "Rulesets",
				"Rule Designer", "Rule Editing", "Code Repos", "Image Repos", "Integrations",
				"PR Settings", "Alert Settings", "Logs", "Encryption", "Users", "Roles"), labels);
	}

	@Test
	void databaseConsolePrivilegeIsNotExposed() {
		assertTrue(Arrays.stream(CorePrivilege.values())
				.noneMatch(privilege -> "Database Access".equals(privilege.getPrivilegeName())));
	}
}

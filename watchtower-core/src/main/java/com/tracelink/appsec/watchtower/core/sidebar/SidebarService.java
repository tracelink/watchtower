package com.tracelink.appsec.watchtower.core.sidebar;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Service manages owning the Sidebar objects so that the UI can display them properly with correct
 * authorizations
 */
@Service
public class SidebarService {
	private static final String ASSISTANT_SETTINGS_URL = "/admin/assistant";

	private final List<SidebarMenuGroup> menuGroups = new ArrayList<>();

	public SidebarService() {
		setupDefaults();
	}

	private void setupDefaults() {
		menuGroups.addAll(Arrays.asList(
				// Home, singleton url
				new SidebarMenuGroup().setGroupName("Home").setMaterialIcon("dashboard")
						.setLinks(Collections.singletonList(
								new SidebarLink()
										.setAuthorizationExpression("isAuthenticated()")
										.setUrl("/"))),

				// Pull Requests Menu
				new SidebarMenuGroup().setGroupName("Pull Requests")
						.setMaterialIcon("compare_arrows")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/scan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("New Scan")
										.setMaterialIcon("add")
										.setUrl("/scan")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_SUBMIT_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Results")
										.setMaterialIcon("report_problem")
										.setUrl("/scan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("MCR")
										.setMaterialIcon("report_problem")
										.setUrl("/scan/mcr")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Bypasses")
										.setMaterialIcon("lock_open")
										.setUrl("/scan/bypasses")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Upload Scans Menu
				new SidebarMenuGroup().setGroupName("Upload Scans")
						.setMaterialIcon("backup")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/uploadscan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("New Scan")
										.setMaterialIcon("add")
										.setUrl("/uploadscan")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_SUBMIT_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Results")
										.setMaterialIcon("report_problem")
										.setUrl("/uploadscan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Repository Scans Menu
				new SidebarMenuGroup().setGroupName("Repository Scans")
						.setMaterialIcon("code")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/reposcan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								// The repository inventory; Configuration > Code Repos links to the
								// same page for people who look for repository settings there
								new SidebarLink()
										.setDisplayName("Repositories")
										.setMaterialIcon("list")
										.setUrl("/repositories")
										.setAuthorizationExpression("hasAnyAuthority('"
												+ CorePrivilege.REPO_SETTINGS_VIEW_NAME + "', '"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Results")
										.setMaterialIcon("history")
										.setUrl("/scans/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Image Menu
				new SidebarMenuGroup().setGroupName("Image Scans")
						.setMaterialIcon("developer_board")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/imagescan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Results")
										.setMaterialIcon("report_problem")
										.setUrl("/imagescan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Rules Menu
				new SidebarMenuGroup().setGroupName("Rules")
						.setMaterialIcon("menu")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Rule Work")
										.setMaterialIcon("playlist_add_check")
										.setUrl("/rules/work")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.RULE_MODIFY_NAME + "') or hasAuthority('"
												+ CorePrivilege.RULESETS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Knowledge")
										.setMaterialIcon("library_books")
										.setUrl("/rules/knowledge")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.RULESETS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Rulesets")
										.setMaterialIcon("assignment")
										.setUrl("/rulesets")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.RULESETS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Rule Designer")
										.setMaterialIcon("build")
										.setUrl("/designer")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.RULE_DESIGNER_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Rule Editing")
										.setMaterialIcon("block")
										.setUrl("/rule/edit")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.RULE_MODIFY_NAME + "')"))),
				// Config Menu
				new SidebarMenuGroup().setGroupName("Configuration")
						.setMaterialIcon("settings")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Code Repos")
										.setMaterialIcon("code")
										.setUrl("/repositories")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.REPO_SETTINGS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Image Repos")
										.setMaterialIcon("equalizer")
										.setUrl("/repository/"
												+ ImageScanType.CONTAINER.getTypeName())
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.REPO_SETTINGS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Integrations")
										.setMaterialIcon("list")
										.setUrl("/apisettings")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.API_SETTINGS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("PR Settings")
										.setMaterialIcon("sync")
										.setUrl("/prsettings")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.PR_SETTINGS_VIEW_NAME
												+ "')"),
								new SidebarLink()
										.setDisplayName("Alert Settings")
										.setMaterialIcon("notifications")
										.setUrl("/alertsettings")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.ALERT_SETTINGS_VIEW_NAME
												+ "')"))),
				// Admin Menu
				new SidebarMenuGroup().setGroupName("Administration")
						.setMaterialIcon("https")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Logs")
										.setMaterialIcon("list")
										.setUrl("/logging")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.LOGGING_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Encryption")
										.setMaterialIcon("vpn_key")
										.setUrl("/encryption")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.ENCRYPTION_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Users")
										.setMaterialIcon("account_circle")
										.setUrl("/usermgmt")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.USER_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Roles")
										.setMaterialIcon("verified_user")
										.setUrl("/rolemgmt")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.ROLE_VIEW_NAME + "')")))
				// End of Groups
		));
	}

	public List<SidebarMenuGroup> getMenuGroups() {
		return menuGroups;
	}

	/**
	 * Adds a module's page to an existing menu group, after the group's own links. Adding a link
	 * for a URL the group already has is a no-op, so a module rebuilt in the same context does
	 * not duplicate it.
	 *
	 * @param groupName the {@link SidebarMenuGroup#getGroupName()} to add to
	 * @param link      the link to add
	 * @throws IllegalArgumentException if no such group exists
	 */
	public synchronized void addLink(String groupName, SidebarLink link) {
		SidebarMenuGroup group = menuGroups.stream()
				.filter(candidate -> candidate.getGroupName().equals(groupName)).findFirst()
				.orElseThrow(() -> new IllegalArgumentException(
						"No sidebar group named " + groupName));
		boolean alreadyPresent = group.getLinks().stream()
				.anyMatch(existing -> Objects.equals(existing.getUrl(), link.getUrl()));
		if (alreadyPresent) {
			return;
		}
		List<SidebarLink> links = new ArrayList<>(group.getLinks());
		links.add(link);
		group.setLinks(List.copyOf(links));
	}

	/**
	 * Resolves which sidebar {@link SidebarMenuGroup#getGroupName()} the given request path
	 * belongs to, for rendering a static "Section" breadcrumb above a page's title. Two tiers,
	 * since not every real page URL is nested under a link this sidebar actually lists (e.g. a
	 * report-detail page like {@code /imagescan/report/5} has no {@code /imagescan/...} sibling
	 * link it is a path-prefix of):
	 * <ol>
	 * <li>Prefer the longest sidebar link URL that the path equals or is nested under (e.g.
	 * {@code /scan/mcr/report/5} resolves via {@code /scan/mcr}, not the shorter {@code
	 * /scan}).</li>
	 * <li>Otherwise, fall back to matching just the first path segment against each link's first
	 * path segment (this is what actually resolves {@code /imagescan/report/5}, since no
	 * Image Scans link is itself a prefix of it, but {@code /imagescan/dashboard} shares the
	 * same first segment).</li>
	 * </ol>
	 *
	 * @param path the request path, e.g. {@code request.getRequestURI()}
	 * @return the owning group's name, or empty if no sidebar link's URL shares a first path
	 *         segment with it (e.g. {@code /profile}, which is intentionally not on the
	 *         sidebar)
	 */
	public Optional<String> getGroupNameForPath(String path) {
		if (path.equals("/reposcan") || path.startsWith("/reposcan/")) {
			path = "/scans/results";
		} else if (path.equals("/repository/pull_request")
				|| path.startsWith("/repository/pull_request/")) {
			path = "/repositories";
		}
		String bestGroupName = null;
		int bestUrlLength = -1;
		for (SidebarMenuGroup group : menuGroups) {
			for (SidebarLink link : group.getLinks()) {
				String url = link.getUrl();
				if (link.isExternalLink()) {
					continue;
				}
				if ((path.equals(url) || path.startsWith(url + "/")) && url.length() > bestUrlLength) {
					bestGroupName = group.getGroupName();
					bestUrlLength = url.length();
				}
			}
		}
		if (bestGroupName != null) {
			return Optional.of(bestGroupName);
		}

		String firstSegment = firstPathSegment(path);
		for (SidebarMenuGroup group : menuGroups) {
			for (SidebarLink link : group.getLinks()) {
				if (!link.isExternalLink() && firstSegment.equals(firstPathSegment(link.getUrl()))) {
					return Optional.of(group.getGroupName());
				}
			}
		}
		return Optional.empty();
	}

	/**
	 * Builds the navigable ancestors shown ahead of the current page title. The trail mirrors the
	 * sidebar hierarchy and adds the nearest menu destination, including explicit parents for
	 * report routes that are not themselves present in the sidebar.
	 *
	 * @param path request path
	 * @return ordered, clickable breadcrumb ancestors
	 */
	public List<BreadcrumbLink> getBreadcrumbLinksForPath(String path) {
		if ("/".equals(path)) {
			return Collections.emptyList();
		}

		// The AI assistant settings link is in the sidebar template, not in a menu group, so its
		// sub-pages (Answer evaluation, transcripts) name it explicitly instead of falling back to Home.
		if (path.startsWith(ASSISTANT_SETTINGS_URL + "/")) {
			return List.of(new BreadcrumbLink("AI assistant settings", ASSISTANT_SETTINGS_URL));
		}
		NavigationTarget target = reportParent(path).orElseGet(() -> findNavigationTarget(path));
		if (target == null) {
			return Collections.singletonList(new BreadcrumbLink("Home", "/"));
		}

		String destination = normalizeDestination(target.link().getUrl());
		List<BreadcrumbLink> links = new ArrayList<>();
		links.add(new BreadcrumbLink(target.group().getGroupName(), destination));
		if (target.link().getDisplayName() != null) {
			links.add(new BreadcrumbLink(target.link().getDisplayName(), destination));
		}
		return List.copyOf(links);
	}

	private Optional<NavigationTarget> reportParent(String path) {
		if (path.startsWith("/scan/mcr/report/")) {
			return findTargetByUrl("/scan/mcr");
		}
		if (path.startsWith("/scan/report/")) {
			return findTargetByUrl("/scan/results");
		}
		if (path.startsWith("/uploadscan/report/")) {
			return findTargetByUrl("/uploadscan/results");
		}
		if (path.startsWith("/imagescan/report/")) {
			return findTargetByUrl("/imagescan/results");
		}
		if (path.equals("/reposcan") || path.startsWith("/reposcan/")) {
			return findTargetByUrl("/scans/results");
		}
		if (path.equals("/repository/pull_request")
				|| path.startsWith("/repository/pull_request/")) {
			return findTargetByUrl("/repositories");
		}
		return Optional.empty();
	}

	private NavigationTarget findNavigationTarget(String path) {
		NavigationTarget bestTarget = null;
		int bestUrlLength = -1;
		for (SidebarMenuGroup group : menuGroups) {
			for (SidebarLink link : group.getLinks()) {
				String url = link.getUrl();
				if (!link.isExternalLink()
						&& (path.equals(url) || path.startsWith(url + "/"))
						&& url.length() > bestUrlLength) {
					bestTarget = new NavigationTarget(group, link);
					bestUrlLength = url.length();
				}
			}
		}
		if (bestTarget != null) {
			return bestTarget;
		}

		String firstSegment = firstPathSegment(path);
		for (SidebarMenuGroup group : menuGroups) {
			for (SidebarLink link : group.getLinks()) {
				if (!link.isExternalLink()
						&& firstSegment.equals(firstPathSegment(link.getUrl()))) {
					return new NavigationTarget(group, link);
				}
			}
		}
		return null;
	}

	private Optional<NavigationTarget> findTargetByUrl(String url) {
		for (SidebarMenuGroup group : menuGroups) {
			for (SidebarLink link : group.getLinks()) {
				if (!link.isExternalLink() && url.equals(link.getUrl())) {
					return Optional.of(new NavigationTarget(group, link));
				}
			}
		}
		return Optional.empty();
	}

	private static String normalizeDestination(String url) {
		return switch (url) {
			case "/scan/results" -> "/scan/results/all";
			case "/uploadscan/results" -> "/uploadscan/results/all";
			case "/imagescan/results" -> "/imagescan/results/all";
			default -> url;
		};
	}

	private static String firstPathSegment(String path) {
		String[] segments = path.split("/");
		for (String segment : segments) {
			if (!segment.isEmpty()) {
				return segment;
			}
		}
		return "";
	}

	private record NavigationTarget(SidebarMenuGroup group, SidebarLink link) {
	}

}

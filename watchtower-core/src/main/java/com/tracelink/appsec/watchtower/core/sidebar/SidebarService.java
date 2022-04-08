package com.tracelink.appsec.watchtower.core.sidebar;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;

/**
 * Service manages owning the Sidebar objects so that the UI can display them properly with correct
 * authorizations
 */
@Service
public class SidebarService {
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
										.setDisplayName("Pull Request Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/scan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Pull Request Scan")
										.setMaterialIcon("add")
										.setUrl("/scan")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_SUBMIT_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Pull Request Scan Results")
										.setMaterialIcon("report_problem")
										.setUrl("/scan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Upload Scans Menu
				new SidebarMenuGroup().setGroupName("Upload Scans")
						.setMaterialIcon("backup")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Upload Scan Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/uploadscan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Upload Scan")
										.setMaterialIcon("add")
										.setUrl("/uploadscan")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_SUBMIT_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Upload Scan Results")
										.setMaterialIcon("report_problem")
										.setUrl("/uploadscan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Image Menu
				new SidebarMenuGroup().setGroupName("Image Scans")
						.setMaterialIcon("developer_board")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Image Scan Dashboard")
										.setMaterialIcon("dashboard")
										.setUrl("/imagescan/dashboard")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_DASHBOARDS_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Image Scan Results")
										.setMaterialIcon("report_problem")
										.setUrl("/imagescan/results")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.SCAN_RESULTS_NAME + "')"))),
				// Rules Menu
				new SidebarMenuGroup().setGroupName("Rules")
						.setMaterialIcon("menu")
						.setLinks(Arrays.asList(
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
										.setDisplayName("Repository Settings")
										.setMaterialIcon("code")
										.setUrl("/repository")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.REPO_SETTINGS_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("SCM API Settings")
										.setMaterialIcon("list")
										.setUrl("/apisettings")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.API_SETTINGS_VIEW_NAME + "')"))),
				// Admin Menu
				new SidebarMenuGroup().setGroupName("Administration")
						.setMaterialIcon("https")
						.setLinks(Arrays.asList(
								new SidebarLink()
										.setDisplayName("Logging")
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
										.setDisplayName("User Management")
										.setMaterialIcon("account_circle")
										.setUrl("/usermgmt")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.USER_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("Role Management")
										.setMaterialIcon("verified_user")
										.setUrl("/rolemgmt")
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.ROLE_VIEW_NAME + "')"),
								new SidebarLink()
										.setDisplayName("DB Console")
										.setMaterialIcon("memory")
										.setUrl("/console")
										.setExternalLink(true)
										.setAuthorizationExpression("hasAuthority('"
												+ CorePrivilege.DB_ACCESS_NAME + "')")))
		// End of Groups
		));
	}

	public List<SidebarMenuGroup> getMenuGroups() {
		return menuGroups;
	}

}

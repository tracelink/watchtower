package com.tracelink.appsec.watchtower.core.sidebar;

/**
 * Object descriptor for a link on the sidebar. Used by the UI to display the dropdown menus
 * 
 * @author csmith
 *
 */
public class SidebarLink {
	private String displayName;
	private String authorization;
	private String url;
	private String materialIcon;
	private boolean externalLink = false;

	public String getDisplayName() {
		return displayName;
	}

	public SidebarLink setDisplayName(String displayName) {
		this.displayName = displayName;
		return this;
	}

	public String getAuthorizationExpression() {
		return authorization;
	}

	public SidebarLink setAuthorizationExpression(String authorization) {
		this.authorization = authorization;
		return this;
	}

	public String getUrl() {
		return url;
	}

	public SidebarLink setUrl(String url) {
		this.url = url;
		return this;
	}

	public String getMaterialIcon() {
		return materialIcon;
	}

	public SidebarLink setMaterialIcon(String materialIcon) {
		this.materialIcon = materialIcon;
		return this;
	}

	public boolean isExternalLink() {
		return externalLink;
	}

	public SidebarLink setExternalLink(boolean externalLink) {
		this.externalLink = externalLink;
		return this;
	}

}

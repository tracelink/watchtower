package com.tracelink.appsec.watchtower.core.sidebar;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Object descriptor for a sidebar dropdown menu. Used by the UI to collect
 * {@linkplain SidebarLink}s into dropdowns
 * 
 * @author csmith
 *
 */
public class SidebarMenuGroup {
	private String groupName;
	private String materialIcon;
	private List<SidebarLink> links;

	public String getGroupName() {
		return groupName;
	}

	public SidebarMenuGroup setGroupName(String groupName) {
		this.groupName = groupName;
		return this;
	}

	public String getMaterialIcon() {
		return materialIcon;
	}

	public SidebarMenuGroup setMaterialIcon(String materialIcon) {
		this.materialIcon = materialIcon;
		return this;
	}

	public List<SidebarLink> getLinks() {
		return links;
	}

	public SidebarMenuGroup setLinks(List<SidebarLink> links) {
		this.links = links;
		return this;
	}

	public String getAuthorizationExpression() {
		return getLinks().stream().map(SidebarLink::getAuthorizationExpression)
				.collect(Collectors.joining(" or "));
	}


}

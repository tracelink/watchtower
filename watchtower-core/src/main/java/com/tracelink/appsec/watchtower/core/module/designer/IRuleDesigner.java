package com.tracelink.appsec.watchtower.core.module.designer;

import org.apache.commons.codec.binary.StringUtils;

/**
 * The Rule Designer is in charge of owning the Rule Designer User Experience for a module
 * 
 * @author csmith
 *
 */
public interface IRuleDesigner {
	/**
	 * Create a new Rule Designer MAV that will be integrated into the Watchtower UI.
	 * 
	 * @return a {@link RuleDesignerModelAndView} for this module's Rule Designer
	 */
	RuleDesignerModelAndView getDefaultRuleDesignerModelAndView();

	String getPrivilegeNameForAccess();

	default boolean hasAuthority(String authority) {
		return StringUtils.equals(authority, getPrivilegeNameForAccess());
	}

}

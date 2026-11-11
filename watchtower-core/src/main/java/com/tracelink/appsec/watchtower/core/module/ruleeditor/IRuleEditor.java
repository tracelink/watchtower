package com.tracelink.appsec.watchtower.core.module.ruleeditor;


import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * The Rule Editor is in charge of owning the Rule Edit/Save User Experience for a module
 * 
 * @author csmith
 *
 */
public interface IRuleEditor {

	/**
	 * Given a Rule, return the Rule Edit MAV showing edit options for this rule.
	 * 
	 * @param rule the rule to edit
	 * @return a {@link RuleEditModelAndView} used to edit this rule.
	 */
	RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule);

	/**
	 * Return the named Privilege used to check if a user has the authority to access this rule
	 * editor. Null or empty string privilege means all users have access.
	 * 
	 * @return a privilege name denoting authority needed to access this editor, or null/empty
	 *         string for all users have access
	 */
	String getPrivilegeNameForAccess();

	default boolean hasAuthority(String authority) {
		if (StringUtils.isBlank(getPrivilegeNameForAccess())) {
			return true;
		}
		return StringUtils.equals(authority, getPrivilegeNameForAccess());
	}
}

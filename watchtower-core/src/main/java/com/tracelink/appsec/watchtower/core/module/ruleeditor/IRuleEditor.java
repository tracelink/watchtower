package com.tracelink.appsec.watchtower.core.module.ruleeditor;

import org.apache.commons.codec.binary.StringUtils;

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
	RuleEditModelAndView getRuleEditModelAndView(RuleDto rule);

	String getPrivilegeNameForAccess();

	default boolean hasAuthority(String authority) {
		return StringUtils.equals(authority, getPrivilegeNameForAccess());
	}
}

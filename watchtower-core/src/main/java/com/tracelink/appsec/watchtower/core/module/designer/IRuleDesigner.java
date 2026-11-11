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

	/**
	 * The designer opened from a drafted rule: the rule and its examples are filled in and, where the engine can
	 * test a rule, the example has already been run. Nothing is saved. A designer that cannot show a draft keeps
	 * the default page.
	 *
	 * @param draft the draft to show
	 * @return the designer page with the draft filled in
	 */
	default RuleDesignerModelAndView getPrefilledRuleDesignerModelAndView(RuleDraftData draft) {
		return getDefaultRuleDesignerModelAndView();
	}

	/**
	 * Checks a draft meant for this designer before it is stored (for example that a regex compiles).
	 *
	 * @param draft the draft to check
	 * @return a plain sentence saying what is wrong, or null when the draft is acceptable
	 */
	default String validateDraft(RuleDraftData draft) {
		return null;
	}

	String getPrivilegeNameForAccess();

	default boolean hasAuthority(String authority) {
		return StringUtils.equals(authority, getPrivilegeNameForAccess());
	}

}

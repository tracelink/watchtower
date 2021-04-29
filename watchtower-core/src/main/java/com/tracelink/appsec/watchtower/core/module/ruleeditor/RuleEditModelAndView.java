package com.tracelink.appsec.watchtower.core.module.ruleeditor;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * This MAV provides a basic wrapper around the {@link WatchtowerModelAndView} in order to correctly
 * integrate the UI for a module's Rule Editor into the Watchtower UI
 * 
 * @author csmith
 *
 */
public class RuleEditModelAndView extends WatchtowerModelAndView {
	public static final String RULE_VIEW = "ruleView";

	public RuleEditModelAndView(String ruleEditView) {
		super("rules/rule-edit");
		addObject(RULE_VIEW, ruleEditView);
		addScriptReference("/scripts/rule-edit.js");
	}


}

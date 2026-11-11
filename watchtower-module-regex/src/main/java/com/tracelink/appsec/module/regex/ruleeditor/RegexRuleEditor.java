package com.tracelink.appsec.module.regex.ruleeditor;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of the Rule Editor for Regex
 * 
 * @author csmith
 *
 */
public class RegexRuleEditor implements IRuleEditor {

	@Override
	public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
		RuleEditModelAndView mav = new RuleEditModelAndView("rule-edit/regex");
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME;
	}
}

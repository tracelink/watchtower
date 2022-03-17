package com.tracelink.appsec.module.checkov.editor;

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of an {@link IRuleEditor} for Checkov rules. Only handles/allows editing priority
 * of core rules
 *
 * @author csmith
 */
public class CheckovRuleEditor implements IRuleEditor {

	@Override
	public RuleEditModelAndView getRuleEditModelAndView(RuleDto rule) {
		String ruleEditView = "rule-edit/checkov-core";
		RuleEditModelAndView mav = new RuleEditModelAndView(ruleEditView);
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME;
	}

}

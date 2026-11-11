package com.tracelink.appsec.module.pmd.ruleeditor;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of the PMD Rule Editor
 * 
 * @author csmith
 *
 */
public class PMDRuleEditor implements IRuleEditor {
	@Override
	public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
		RuleEditModelAndView mav = new RuleEditModelAndView("rule-edit/pmd");
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME;
	}
}

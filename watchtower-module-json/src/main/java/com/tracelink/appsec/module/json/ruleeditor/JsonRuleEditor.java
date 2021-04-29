package com.tracelink.appsec.module.json.ruleeditor;

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of the Rule Editor for Json
 * 
 * @author csmith
 *
 */
public class JsonRuleEditor implements IRuleEditor {

	@Override
	public RuleEditModelAndView getRuleEditModelAndView(RuleDto rule) {
		RuleEditModelAndView mav = new RuleEditModelAndView("rule-edit/json");
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return JsonModule.JSON_RULE_EDITOR_PRIVILEGE_NAME;
	}

}

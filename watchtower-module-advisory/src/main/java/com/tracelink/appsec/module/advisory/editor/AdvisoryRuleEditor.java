package com.tracelink.appsec.module.advisory.editor;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Implementation of {@linkplain IRuleEditor} for the Advisory Rules
 * 
 * @author csmith
 *
 */
public class AdvisoryRuleEditor implements IRuleEditor {
	@Override
	public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
		RuleEditModelAndView mav = new RuleEditModelAndView("rule-edit/advisory");
		mav.addObject("rule", rule);
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return AdvisoryModule.ADVISORY_RULE_EDITOR_PRIVILEGE_NAME;
	}

}

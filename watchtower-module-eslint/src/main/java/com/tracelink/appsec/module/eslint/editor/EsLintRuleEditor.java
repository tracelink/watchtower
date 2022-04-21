package com.tracelink.appsec.module.eslint.editor;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of an {@link IRuleEditor} for ESLint rules. Returns two different rule editor
 * views depending on whether the rule is custom or core.
 *
 * @author mcool
 */
public class EsLintRuleEditor implements IRuleEditor {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
		boolean core = rule.isProvided();
		String ruleEditView = core ? "rule-edit/eslint-core" : "rule-edit/eslint";
		RuleEditModelAndView mav = new RuleEditModelAndView(ruleEditView);
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		if (!core) {
			mav.addScriptReference("/scripts/eslint-editor.js");
		}
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME;
	}
}

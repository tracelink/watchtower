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
			// codemirror-bundle.js must be registered before eslint-editor.js: unlike the
			// designer pages (whose base RuleDesignerModelAndView always registers it),
			// RuleEditModelAndView never does, so eslint-editor.js's CodeMirror.fromTextArea
			// call was throwing "CodeMirror is not defined" on every custom rule's edit page -
			// pre-existing, confirmed via git history (commit 692ae82), unrelated to the
			// Material Web migration. The plain #createFunction textarea still rendered and
			// round-tripped its content correctly since CodeMirror never ran to hide it, so this
			// was cosmetic (no syntax highlighting), not a functional break.
			mav.addScriptReference("/scripts/codemirror-bundle.js");
			mav.addScriptReference("/scripts/eslint-editor.js");
		}
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME;
	}
}

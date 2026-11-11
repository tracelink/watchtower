package com.tracelink.appsec.module.betterleaks.editor;

import java.util.List;
import java.util.function.LongFunction;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.designer.BetterleaksCustomRuleForm;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Rule editor for Betterleaks rules. Provided rules can only change priority; custom rules can
 * change their detection fields too, and show their version history.
 *
 * @author Watchtower
 */
public class BetterleaksRuleEditor implements IRuleEditor {

	static final String EDIT_VIEW = "rule-edit/betterleaks-provided";

	static final String CUSTOM_EDIT_VIEW = "rule-edit/betterleaks-custom";

	private final LongFunction<List<BetterleaksRuleVersionEntity>> versions;

	public BetterleaksRuleEditor() {
		this(ruleId -> List.of());
	}

	/**
	 * @param versions looks up a custom rule's saved versions
	 */
	public BetterleaksRuleEditor(LongFunction<List<BetterleaksRuleVersionEntity>> versions) {
		this.versions = versions;
	}

	@Override
	public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
		if (rule instanceof BetterleaksCustomRuleDto custom) {
			RuleEditModelAndView mav = new RuleEditModelAndView(CUSTOM_EDIT_VIEW);
			mav.addObject("rule", custom);
			mav.addObject("form", BetterleaksCustomRuleForm.fromRule(custom));
			mav.addObject("priorities", RulePriority.values());
			mav.addObject("versions",
					custom.getId() == null ? List.of() : versions.apply(custom.getId()));
			return mav;
		}
		RuleEditModelAndView mav = new RuleEditModelAndView(EDIT_VIEW);
		mav.addObject("rule", rule);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME;
	}
}

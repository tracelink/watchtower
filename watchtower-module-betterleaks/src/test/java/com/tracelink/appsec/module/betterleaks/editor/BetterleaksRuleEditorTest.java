package com.tracelink.appsec.module.betterleaks.editor;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksRuleEditorTest {

	@Test
	public void testEditViewOffersEveryPriorityForTheRule() {
		BetterleaksProvidedRuleDto rule = new BetterleaksProvidedRuleDto();

		RuleEditModelAndView mav = new BetterleaksRuleEditor().getDefaultRuleEditModelAndView(rule);

		MatcherAssert.assertThat(mav.getModel().get("rule"), Matchers.sameInstance(rule));
		Assertions.assertArrayEquals(RulePriority.values(),
				(RulePriority[]) mav.getModel().get("priorities"));
	}

	@Test
	public void testCustomRuleGetsItsFormAndVersionHistory() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		rule.setId(9L);
		java.util.List<com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity> history =
				java.util.List.of(new com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity());

		RuleEditModelAndView mav = new BetterleaksRuleEditor(ruleId -> {
			Assertions.assertEquals(9L, ruleId);
			return history;
		}).getDefaultRuleEditModelAndView(rule);

		Assertions.assertSame(history, mav.getModel().get("versions"));
		Assertions.assertEquals(rule.getRegex(),
				((com.tracelink.appsec.module.betterleaks.designer.BetterleaksCustomRuleForm) mav
						.getModel().get("form")).getRegex());
	}

	@Test
	public void testEditingNeedsTheRuleEditorPrivilege() {
		Assertions.assertEquals(BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME,
				new BetterleaksRuleEditor().getPrivilegeNameForAccess());
	}
}

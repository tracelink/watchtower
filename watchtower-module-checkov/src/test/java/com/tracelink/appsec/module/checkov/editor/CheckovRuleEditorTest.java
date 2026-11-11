package com.tracelink.appsec.module.checkov.editor;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;

public class CheckovRuleEditorTest {

	@Mock
	private CheckovProvidedRuleDto ruleDto;

	@Test
	public void testGetRuleEditModelAndView() {
		CheckovRuleEditor editor = new CheckovRuleEditor();
		RuleEditModelAndView mav = editor.getDefaultRuleEditModelAndView(ruleDto);
		MatcherAssert.assertThat(mav.getModel().get(RuleEditModelAndView.RULE_VIEW),
				Matchers.is("rule-edit/checkov-core"));
		MatcherAssert.assertThat(mav.getModel().get("rule"), Matchers.is(ruleDto));
	}
}

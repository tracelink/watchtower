package com.tracelink.appsec.module.eslint.designer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/** A drafted ESLint rule is shown for review. It is JavaScript that would run, so nothing runs until the person asks. */
public class EsLintRuleDesignerDraftTest {
	private static final String FUNCTION = "create(context) { return { BinaryExpression(node) { if (node.operator === '==') "
			+ "{ context.report({ node, messageId: 'violation' }); } } }; }";
	private final LinterEngine engine = mock(LinterEngine.class);
	private final EsLintRuleDesigner designer = new EsLintRuleDesigner(engine);

	private static RuleDraftData draft(String function) {
		return new RuleDraftData("id", "eslint", null, "Use ===", "Use === instead of ==.", 3, "CWE-697", null, function, null,
				"if (a == b) {}", "if (a === b) {}", "Loose equality coerces values.", "Coverage gap: CWE-697");
	}

	@Test
	public void theDraftedFunctionIsShownWithItsExampleAndTheEngineIsNotTouched() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(draft(FUNCTION));

		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		assertThat(rule.getName()).isEqualTo("Use ===");
		assertThat(rule.getMessage()).isEqualTo("Use === instead of ==.");
		assertThat(rule.getPriority()).isEqualTo(RulePriority.MEDIUM);
		assertThat(rule.getCreateFunction()).isEqualTo(FUNCTION);
		assertThat(rule.getMessages()).hasSize(1);
		assertThat(rule.getMessages().get(0).getKey()).isEqualTo("violation");
		assertThat(rule.getMessages().get(0).getValue()).isEqualTo("Use === instead of ==.");
		assertThat(mav.getModel().get("sourceCode")).isEqualTo("if (a == b) {}");
		assertThat(mav.getModel()).doesNotContainKeys("matches", "ast");
		verifyNoInteractions(engine);
	}

	@Test
	public void aFunctionThatNeverReportsIsRefused() {
		assertThat(designer.validateDraft(draft("create(context) { return {}; }"))).startsWith("An ESLint rule needs");
		assertThat(designer.validateDraft(draft("nothing here"))).startsWith("An ESLint rule needs");
		assertThat(designer.validateDraft(draft(FUNCTION))).isNull();
	}
}

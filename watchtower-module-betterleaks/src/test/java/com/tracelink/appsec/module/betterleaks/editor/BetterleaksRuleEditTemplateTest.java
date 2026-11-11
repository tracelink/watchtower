package com.tracelink.appsec.module.betterleaks.editor;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksCategory;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Renders the Betterleaks rule-edit fragments. Regression for Dev v26.1.79: /rule/edit/betterleaks
 * never loaded because the provided-rule fragment called {@code isBlank()} on the category enum,
 * which failed mid-render after the page had started streaming and cut the response off.
 */
class BetterleaksRuleEditTemplateTest {

	private static String render(RuleEditModelAndView mav) {
		ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
		resolver.setPrefix("templates/");
		resolver.setSuffix(".html");
		resolver.setTemplateMode("HTML");
		SpringTemplateEngine engine = new SpringTemplateEngine();
		engine.setTemplateResolver(resolver);
		Context context = new Context();
		context.setVariables(mav.getModel());
		context.setVariable("_csrf", Map.of("parameterName", "_csrf", "token", "token"));
		// The page shell needs a signed-in user; the module's own fragment is what broke.
		return engine.process((String) mav.getModel().get(RuleEditModelAndView.RULE_VIEW), context);
	}

	@Test
	void providedRuleRendersItsCategoryInPlainWords() {
		BetterleaksProvidedRuleDto rule = new BetterleaksProvidedRuleDto();
		rule.setName("Betterleaks: aws-access-token");
		rule.setMessage("An AWS access key.");
		rule.setExternalUrl("https://example.invalid/aws");
		rule.setCategory(BetterleaksCategory.CLOUD);
		rule.setConfidence("high");
		rule.setPriority(RulePriority.HIGH);

		String html = render(new BetterleaksRuleEditor().getDefaultRuleEditModelAndView(rule));

		assertTrue(html.contains(">Cloud<"), html);
		assertTrue(html.contains("High confidence"), html);
		assertTrue(html.contains("Save severity"), html);
	}

	@Test
	void providedRuleWithoutCategoryOrConfidenceStillRenders() {
		BetterleaksProvidedRuleDto rule = new BetterleaksProvidedRuleDto();
		rule.setName("Betterleaks: generic-api-key");
		rule.setPriority(RulePriority.MEDIUM);

		String html = render(new BetterleaksRuleEditor().getDefaultRuleEditModelAndView(rule));

		assertTrue(html.contains("Save severity"), html);
	}

	@Test
	void customRuleRendersWithVersionHistory() {
		var rule = BetterleaksCustomRuleDtoTest.validRule();
		rule.setId(4L);

		String html = render(new BetterleaksRuleEditor(id -> List.of())
				.getDefaultRuleEditModelAndView(rule));

		assertTrue(html.contains("Test and save version"), html);
		assertTrue(html.contains("Version history (0)"), html);
	}
}

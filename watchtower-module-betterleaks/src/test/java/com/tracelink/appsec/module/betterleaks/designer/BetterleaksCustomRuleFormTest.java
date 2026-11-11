package com.tracelink.appsec.module.betterleaks.designer;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksCustomRuleFormTest {

	static BetterleaksCustomRuleForm form() {
		BetterleaksCustomRuleForm form = new BetterleaksCustomRuleForm();
		form.setRuleId(" custom-example-internal-token ");
		form.setDescription("An example internal service token.");
		form.setExternalUrl("https://wiki.example.invalid/secrets");
		form.setPriority("HIGH");
		form.setRegex("tlk_int_[A-Za-z0-9]{16}");
		form.setKeywords(" tlk_int_ , tlk_svc_ ,");
		form.setEntropy("3.0");
		form.setSecretGroup("");
		form.setFilter("");
		form.setPositiveSample("token = tlk_int_Q7m2Zp9Xc4Vb8Nn1");
		form.setNegativeSample("token = tlk_int_short");
		return form;
	}

	@Test
	public void testBuildsTheRuleAndItsWatchtowerName() {
		BetterleaksCustomRuleDto rule = form().toRule();

		Assertions.assertEquals("custom-example-internal-token", rule.getBetterleaksId());
		Assertions.assertEquals("Betterleaks: custom-example-internal-token", rule.getName());
		Assertions.assertEquals(RulePriority.HIGH, rule.getPriority());
		Assertions.assertEquals(List.of("tlk_int_", "tlk_svc_"), rule.getKeywords());
		Assertions.assertEquals(3.0, rule.getEntropy());
		Assertions.assertNull(rule.getSecretGroup());
		Assertions.assertNull(rule.getFilter());
		Assertions.assertEquals(List.of(), rule.fieldProblems());
	}

	@Test
	public void testUnparseableNumbersAndPrioritiesAreReportedWithoutEchoingThem() {
		BetterleaksCustomRuleForm badEntropy = form();
		badEntropy.setEntropy("<script>");
		BetterleaksCustomRuleForm badPriority = form();
		badPriority.setPriority("<b>URGENT</b>");
		BetterleaksCustomRuleForm badGroup = form();
		badGroup.setSecretGroup("one");

		for (BetterleaksCustomRuleForm bad : List.of(badEntropy, badPriority, badGroup)) {
			IllegalArgumentException e =
					Assertions.assertThrows(IllegalArgumentException.class, bad::toRule);
			MatcherAssert.assertThat(e.getMessage(), Matchers.not(Matchers.containsString("<")));
		}
	}

	@Test
	public void testRoundTripsAnExistingRuleForEditing() {
		BetterleaksCustomRuleDto original = BetterleaksCustomRuleDtoTest.validRule();

		BetterleaksCustomRuleDto copy = BetterleaksCustomRuleForm.fromRule(original).toRule();

		Assertions.assertEquals(original.getBetterleaksId(), copy.getBetterleaksId());
		Assertions.assertEquals(original.getRegex(), copy.getRegex());
		Assertions.assertEquals(original.getKeywords(), copy.getKeywords());
		Assertions.assertEquals(original.getPriority(), copy.getPriority());
		Assertions.assertEquals(original.getPositiveSample(), copy.getPositiveSample());
	}
}

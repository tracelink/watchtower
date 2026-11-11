package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDProvidedRuleDto;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/** Cross-module contract checks without an application context or external services. */
class RuleExecutionContractTest {

	static Stream<RuleDto> definitions() {
		RegexCustomRuleDto regex = new RegexCustomRuleDto();
		regex.setFileExtension(".java");
		regex.setRegexPattern("unsafe\\(");
		RegexProvidedRuleDto providedRegex = new RegexProvidedRuleDto();
		providedRegex.setFileExtension(".js");
		providedRegex.setRegexPattern("unsafe\\(");
		JsonRuleDto json = new JsonRuleDto();
		json.setFileExtension(".json");
		json.setQuery("$.unsafe");
		PMDCustomRuleDto pmd = new PMDCustomRuleDto();
		pmd.setParserLanguage("java");
		pmd.setRuleClass("net.sourceforge.pmd.lang.rule.xpath.XPathRule");
		pmd.setProperties(List.of(property("xpath", "//MethodDeclaration")));
		EsLintCustomRuleDto eslint = new EsLintCustomRuleDto();
		eslint.setCreateFunction("create(context) { return {}; }");
		eslint.setSchema("[]");
		eslint.setMessages(List.of(new EsLintMessageDto("unsafe", "Unsafe call")));
		BetterleaksCustomRuleDto betterleaks = new BetterleaksCustomRuleDto();
		betterleaks.setBetterleaksId("custom-example");
		betterleaks.setRegex("EXAMPLE_[a-z]{10}");
		betterleaks.setPositiveSample("EXAMPLE_abcdefghij");
		betterleaks.setNegativeSample("clean");
		BetterleaksProvidedRuleDto providedBetterleaks = new BetterleaksProvidedRuleDto();
		providedBetterleaks.setBetterleaksId("generic-api-key");
		return Stream.of(regex, providedRegex, json, pmd, new PMDProvidedRuleDto(), eslint,
				new EsLintProvidedRuleDto(), new CheckovProvidedRuleDto(), new AdvisoryRuleDto(),
				betterleaks, providedBetterleaks).peek(rule -> {
				rule.setId(123L);
				rule.setName("example");
				rule.setPriority(RulePriority.MEDIUM);
			});
	}

	@ParameterizedTest
	@MethodSource("definitions")
	void entityRoundTripAndStewardshipDoNotChangeDefinition(RuleDto rule) {
		String revision = rule.getRevision();
		assertNotNull(revision, rule.getClass().getSimpleName());
		assertEquals(64, revision.length());
		assertEquals(revision, rule.toEntity().toDto().getRevision());
		rule.getStewardship().setOwner("new owner");
		rule.getStewardship().setState(RuleState.DEPRECATED);
		rule.setPriority(RulePriority.HIGH);
		rule.setRulesets(Set.of("new membership"));
		if (rule instanceof CustomRuleDto custom) {
			custom.setAuthor("new author");
			custom.setExternalUrl("https://example.com/updated");
		}
		assertEquals(revision, rule.getRevision());
		assertEquals(123L, rule.getExecutionIdentity().ruleId());
		assertNull(rule.toEntity().toDto().getExecutionIdentity().ruleId(),
				"Export ids must never become new entity identities");
	}

	@ParameterizedTest
	@MethodSource("definitions")
	void exportDoesNotExposeIdentityOrRevision(RuleDto rule) {
		var json = new ObjectMapper().valueToTree(rule);
		assertFalse(json.has("revision"));
		assertFalse(json.has("executionIdentity"));
		assertFalse(json.has("externalRuleKey"));
		assertFalse(json.has("stewardship"));
	}

	@Test
	void customRenamePreservesRevisionAndSameNameContentEditChangesIt() {
		definitions().filter(rule -> rule instanceof RegexCustomRuleDto
				|| rule instanceof JsonRuleDto || rule instanceof PMDCustomRuleDto
				|| rule instanceof EsLintCustomRuleDto).forEach(rule -> {
			String original = rule.getRevision();
			rule.setName("renamed");
			assertEquals(original, rule.getRevision());
			if (rule instanceof RegexCustomRuleDto regex) regex.setRegexPattern("changed");
			if (rule instanceof JsonRuleDto json) json.setQuery("$.changed");
			if (rule instanceof PMDCustomRuleDto pmd) pmd.getProperties().get(0).setValue("//Changed");
			if (rule instanceof EsLintCustomRuleDto eslint) eslint.setCreateFunction("create() { return {}; }");
			assertNotEquals(original, rule.getRevision());
		});
	}

	@Test
	void externalSelectorsAndAdvisoryMatcherAreExecutableContent() {
		definitions().filter(rule -> rule instanceof PMDProvidedRuleDto
				|| rule instanceof EsLintProvidedRuleDto || rule instanceof CheckovProvidedRuleDto
				|| rule instanceof AdvisoryRuleDto).forEach(rule -> {
			String original = rule.getRevision();
			rule.setName("another-engine-key");
			assertNotEquals(original, rule.getRevision());
		});
		AdvisoryRuleDto advisory = new AdvisoryRuleDto();
		advisory.setName("CVE-EXAMPLE");
		String original = advisory.getRevision();
		advisory.setName("cve-example");
		assertEquals(original, advisory.getRevision());
		// Match String.equalsIgnoreCase without locale-dependent, multi-character expansions.
		advisory.setName("\u0130");
		original = advisory.getRevision();
		advisory.setName("i");
		assertEquals(original, advisory.getRevision());
		advisory.setName("i\u0307");
		assertNotEquals(original, advisory.getRevision());
	}

	@Test
	void collectionOrderAndChildIdsAreNotDefinitionChanges() {
		PMDCustomRuleDto pmd = new PMDCustomRuleDto();
		PMDPropertyDto first = property("xpath", "//MethodDeclaration");
		PMDPropertyDto second = property("version", "3.1");
		pmd.setProperties(List.of(first, second));
		String original = pmd.getRevision();
		first.setId(999L);
		pmd.setProperties(List.of(second, first));
		assertEquals(original, pmd.getRevision());
		second.setValue("2.0");
		assertNotEquals(original, pmd.getRevision());

		EsLintCustomRuleDto eslint = new EsLintCustomRuleDto();
		EsLintMessageDto a = new EsLintMessageDto("a", "A");
		EsLintMessageDto b = new EsLintMessageDto("b", "B");
		eslint.setMessages(List.of(a, b));
		original = eslint.getRevision();
		a.setId(999);
		eslint.setMessages(List.of(b, a));
		assertEquals(original, eslint.getRevision());
		b.setValue("Changed message");
		assertNotEquals(original, eslint.getRevision());
	}

	@Test
	void ambiguousDuplicateParametersRemainUnknown() {
		PMDCustomRuleDto pmd = new PMDCustomRuleDto();
		pmd.setProperties(List.of(property("xpath", "//One"), property("xpath", "//Two")));
		assertNull(pmd.getRevision());
		EsLintCustomRuleDto eslint = new EsLintCustomRuleDto();
		eslint.setMessages(List.of(new EsLintMessageDto("same", "One"),
				new EsLintMessageDto("same", "Two")));
		assertNull(eslint.getRevision());
	}

	@Test
	void betterleaksHashesExecutionFieldsAndExcludesRegressionSamples() {
		BetterleaksCustomRuleDto rule = new BetterleaksCustomRuleDto();
		rule.setKeywords(List.of("one", "two"));
		rule.setFilter("  size(secret) < 10  ");
		String original = rule.getRevision();
		rule.setKeywords(List.of("two", "one"));
		rule.setFilter("size(secret) < 10");
		rule.setVersion(10);
		rule.setPositiveSample("new synthetic sample");
		rule.setNegativeSample("new negative sample");
		assertEquals(original, rule.getRevision());
		rule.setEntropy(3.5);
		assertNotEquals(original, rule.getRevision());
		original = rule.getRevision();
		rule.setSecretGroup(2);
		assertNotEquals(original, rule.getRevision());
		original = rule.getRevision();
		rule.setBetterleaksId("custom-new-key");
		assertNotEquals(original, rule.getRevision());
	}

	@Test
	void compiledMatchersFollowDtoEdits() {
		RegexCustomRuleDto regex = new RegexCustomRuleDto();
		regex.setRegexPattern("old");
		assertTrue(regex.getCompiledPattern().matcher("old").find());
		regex.setRegexPattern("new");
		assertFalse(regex.getCompiledPattern().matcher("old").find());
		JsonRuleDto json = new JsonRuleDto();
		json.setQuery("$.old");
		assertEquals("$['old']", json.getCompiledQuery().getPath());
		json.setQuery("$.new");
		assertEquals("$['new']", json.getCompiledQuery().getPath());
	}

	private static PMDPropertyDto property(String name, String value) {
		PMDPropertyDto property = new PMDPropertyDto();
		property.setName(name);
		property.setValue(value);
		return property;
	}
}

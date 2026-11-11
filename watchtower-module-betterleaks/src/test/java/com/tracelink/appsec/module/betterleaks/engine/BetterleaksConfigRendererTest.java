package com.tracelink.appsec.module.betterleaks.engine;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistScope;

public class BetterleaksConfigRendererTest {

	private static BetterleaksAllowlistEntry path(String glob, String ruleId) {
		return new BetterleaksAllowlistEntry(BetterleaksAllowlistScope.GLOBAL, null, glob, ruleId);
	}

	@Test
	public void testNoEntriesRendersTheBaseConfig() {
		Assertions.assertEquals(BetterleaksConfigRenderer.BASE_CONFIG,
				BetterleaksConfigRenderer.render(List.of()));
	}

	@Test
	public void testPathEntriesForAllRulesShareOneAllowlist() {
		String toml = BetterleaksConfigRenderer.render(
				List.of(path("src/test/**", null), path("*.lock", null)));

		MatcherAssert.assertThat(toml, Matchers.startsWith(BetterleaksConfigRenderer.BASE_CONFIG));
		Assertions.assertEquals(1, count(toml, "[[allowlists]]"));
		MatcherAssert.assertThat(toml, Matchers.containsString("'''^src/test/.*$'''"));
		MatcherAssert.assertThat(toml, Matchers.containsString("'''^(?:.*/)?[^/]*\\.lock$'''"));
		MatcherAssert.assertThat(toml, Matchers.not(Matchers.containsString("targetRules")));
	}

	@Test
	public void testRuleScopedPathEntriesGetTheirOwnTargetedAllowlist() {
		String toml = BetterleaksConfigRenderer.render(List.of(path("src/test/**", "github-pat"),
				path("docs/**", "github-pat"), path("*.lock", null)));

		Assertions.assertEquals(2, count(toml, "[[allowlists]]"));
		MatcherAssert.assertThat(toml, Matchers.containsString("targetRules = ['github-pat']"));
	}

	@Test
	public void testRuleOnlyEntriesAreNotRenderedHere() {
		// A rule-only entry disables the rule; the scanner leaves it out of --enable-rule.
		Assertions.assertEquals(BetterleaksConfigRenderer.BASE_CONFIG,
				BetterleaksConfigRenderer.render(List.of(path(null, "github-pat"))));
	}

	@Test
	public void testOutputIsStableForTheSameEntries() {
		List<BetterleaksAllowlistEntry> entries =
				List.of(path("b/**", null), path("a/**", "github-pat"), path("a/**", null));

		Assertions.assertEquals(BetterleaksConfigRenderer.render(entries),
				BetterleaksConfigRenderer.render(List.of(entries.get(2), entries.get(1),
						entries.get(0))));
	}

	@Test
	public void testCustomRuleIsRenderedFromItsFieldsOnly() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		rule.setMessage("Say \"no\" to C:\\tokens");
		rule.setFilter("finding[\"secret\"].startsWith(\"tlk_int_test\")");

		String toml = BetterleaksConfigRenderer.render(List.of(), List.of(rule));

		MatcherAssert.assertThat(toml, Matchers.containsString("[[rules]]\n"
				+ "id = 'custom-example-internal-token'\n"
				+ "description = \"Say \\\"no\\\" to C:\\\\tokens\"\n"
				+ "regex = '''tlk_int_[A-Za-z0-9]{16}'''\n"
				+ "keywords = ['tlk_int_']\n"
				+ "entropy = 3.0\n"
				+ "filter = '''finding[\"secret\"].startsWith(\"tlk_int_test\")'''\n"));
		MatcherAssert.assertThat(toml, Matchers.not(Matchers.containsString("secretGroup")));
		MatcherAssert.assertThat(toml, Matchers.not(Matchers.containsString("validate")));
	}

	@Test
	public void testInvalidCustomRuleIsNeverRendered() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		rule.setRegex("x'''\n[[allowlists]]\npaths = ['''.*''']");

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> BetterleaksConfigRenderer.render(List.of(), List.of(rule)));
	}

	@Test
	public void testControlCharactersInADescriptionAreEscaped() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		rule.setMessage("line one\nline two\t\u0001");

		String toml = BetterleaksConfigRenderer.render(List.of(), List.of(rule));

		MatcherAssert.assertThat(toml,
				Matchers.containsString("description = \"line one\\u000Aline two\\u0009\\u0001\""));
	}

	private static int count(String haystack, String needle) {
		return haystack.split(java.util.regex.Pattern.quote(needle), -1).length - 1;
	}
}

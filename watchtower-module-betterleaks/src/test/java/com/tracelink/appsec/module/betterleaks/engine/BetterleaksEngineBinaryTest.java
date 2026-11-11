package com.tracelink.appsec.module.betterleaks.engine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;

/**
 * Runs the real betterleaks binary ({@code WATCHTOWER_BETTERLEAKS_PATH}, or {@code betterleaks} on
 * the PATH) against synthetic fixtures. Skipped when the binary is absent. These pin the
 * behaviour the engine's safety relies on, so a binary upgrade that changes it fails here.
 */
@Tag("requires-binary")
public class BetterleaksEngineBinaryTest {

	/**
	 * Synthetic: matches github-pat's format, belongs to no account. Split so that no secrets
	 * scanner flags this source file.
	 */
	static final String FAKE_PAT = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	@TempDir
	Path target;

	private final AtomicReference<ProcessResult> lastResult = new AtomicReference<>();

	private BetterleaksEngine engine;

	@BeforeEach
	public void setup() {
		ProcessRunner recordingRunner = new ProcessRunner() {
			@Override
			public ProcessResult run(ProcessRequest request) {
				ProcessResult result = super.run(request);
				lastResult.set(result);
				return result;
			}
		};
		engine = new BetterleaksEngine(recordingRunner,
				BetterleaksEngine.resolveBinary(System.getenv()));
		Assumptions.assumeTrue(engine.isAvailable(), "betterleaks binary not installed");
	}

	private Path writeFixture(String relativePath, String content) throws Exception {
		Path file = target.resolve(relativePath);
		Files.createDirectories(file.getParent());
		return Files.writeString(file, content);
	}

	@Test
	public void testFindsASecretUnderTestAndNeverEmitsIt() throws Exception {
		writeFixture("test/Fixture.java", "a\nb\ntoken = \"" + FAKE_PAT + "\"\n");

		List<BetterleaksFinding> findings = engine.scan(target, List.of("github-pat"));

		Assertions.assertEquals(
				List.of(new BetterleaksFinding("github-pat", "test/Fixture.java", 3)), findings);
		MatcherAssert.assertThat(lastResult.get().stdout(),
				Matchers.not(Matchers.containsString(FAKE_PAT)));
		MatcherAssert.assertThat(lastResult.get().stderr(),
				Matchers.not(Matchers.containsString(FAKE_PAT)));
	}

	@Test
	public void testCommittedIgnoreFileDoesNotHideTheSecret() throws Exception {
		Path fixture = writeFixture("src/App.java", "token = \"" + FAKE_PAT + "\"\n");
		writeFixture(".betterleaksignore", fixture + ":github-pat:1\nsrc/App.java:github-pat:1\n"
				+ "./src/App.java:github-pat:1\n");

		Assertions.assertEquals(1, engine.scan(target, List.of("github-pat")).size());
	}

	@Test
	public void testCommittedConfigDoesNotAllowlistTheSecret() throws Exception {
		writeFixture("src/App.java", "token = \"" + FAKE_PAT + "\"\n");
		writeFixture(".betterleaks.toml",
				"[extend]\nuseDefault = true\n[[allowlists]]\npaths = ['''.*''']\n");
		writeFixture(".gitleaks.toml",
				"[extend]\nuseDefault = true\n[[allowlists]]\npaths = ['''.*''']\n");

		Assertions.assertEquals(1, engine.scan(target, List.of("github-pat")).size());
	}

	@Test
	public void testInlineAllowCommentDoesNotHideTheSecret() throws Exception {
		writeFixture("src/App.java", "token = \"" + FAKE_PAT + "\" // betterleaks:allow\n"
				+ "other = \"" + FAKE_PAT + "\" // gitleaks:allow\n");

		Assertions.assertEquals(2, engine.scan(target, List.of("github-pat")).size());
	}

	@Test
	public void testOnlyTheRulesetsRulesRun() throws Exception {
		writeFixture("src/App.java", "token = \"" + FAKE_PAT + "\"\n");

		Assertions.assertEquals(List.of(), engine.scan(target, List.of("slack-bot-token")));
	}

	@Test
	public void testPathAllowlistSilencesOnlyMatchingFiles() throws Exception {
		writeFixture("src/test/fixtures/Token.java", "token = \"" + FAKE_PAT + "\"\n");
		writeFixture("src/main/App.java", "token = \"" + FAKE_PAT + "\"\n");

		List<BetterleaksFinding> findings = engine.scan(target, List.of("github-pat"),
				List.of(entry("src/test/**", null)));

		Assertions.assertEquals(
				List.of(new BetterleaksFinding("github-pat", "src/main/App.java", 1)), findings);
	}

	@Test
	public void testRuleTargetedPathAllowlistLeavesOtherRulesReporting() throws Exception {
		writeFixture("src/test/Fixture.java", "token = \"" + FAKE_PAT + "\"\n"
				+ "slack = \"" + "xoxb-" + "123456789012-1234567890123-abcdefghijABCDEFGHIJklmn"
				+ "\"\n");

		List<BetterleaksFinding> findings = engine.scan(target,
				List.of("github-pat", "slack-bot-token"), List.of(entry("src/test/**",
						"github-pat")));

		Assertions.assertEquals(List.of("slack-bot-token"),
				findings.stream().map(BetterleaksFinding::ruleId).toList());
	}

	private static com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry entry(
			String glob, String ruleId) {
		return new com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry(
				com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistScope.GLOBAL,
				null, glob, ruleId);
	}

	@Test
	public void testCustomRuleIsDetectedInARealScan() throws Exception {
		writeFixture("src/Client.java", "key = \"" + CUSTOM_TOKEN + "\"\n");

		List<BetterleaksFinding> findings = engine.scan(target,
				List.of("custom-example-internal-token"), List.of(), List.of(customRule()));

		Assertions.assertEquals(List.of(new BetterleaksFinding("custom-example-internal-token",
				"src/Client.java", 1)), findings);
		MatcherAssert.assertThat(lastResult.get().stdout(),
				Matchers.not(Matchers.containsString(CUSTOM_TOKEN)));
	}

	@Test
	public void testRuleTesterPassesARuleThatMatchesOnlyItsPositiveSample() {
		BetterleaksRuleTestResult result = engine.testRule(customRule());

		Assertions.assertTrue(result.passed(), result.toString());
		Assertions.assertTrue(result.matchesPositive());
		Assertions.assertFalse(result.matchesNegative());
	}

	@Test
	public void testRuleTesterFailsARuleThatAlsoMatchesItsNegativeSample() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule = customRule();
		rule.setNegativeSample("key = " + "tlk_int_" + "Z9y8X7w6V5u4T3s2");

		BetterleaksRuleTestResult result = engine.testRule(rule);

		Assertions.assertFalse(result.passed());
		Assertions.assertTrue(result.matchesNegative());
	}

	@Test
	public void testRuleTesterReportsTheBinarysReasonForAnInvalidRegex() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule = customRule();
		rule.setRegex("tlk_int_(");

		BetterleaksRuleTestResult result = engine.testRule(rule);

		Assertions.assertFalse(result.passed());
		MatcherAssert.assertThat(result.problem(), Matchers.containsString("regex"));
	}

	@Test
	public void testCustomRuleFilterDropsMatchingFindings() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule = customRule();
		// A filter that evaluates to true drops the finding (verified against 1.8.1).
		rule.setFilter("finding[\"match\"].contains(\"Q7\")");

		// The positive sample now filters itself out, so the rule no longer matches it.
		Assertions.assertFalse(engine.testRule(rule).matchesPositive());
	}

	@Test
	public void testRuleTesterReportsAFilterThatFailsToCompile() {
		// 1.8.1 only warns "rule filter compile error" and keeps every finding, so a filter with
		// a typo would silently never filter anything.
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule = customRule();
		rule.setFilter("no_such_name == 1");

		BetterleaksRuleTestResult result = engine.testRule(rule);

		Assertions.assertFalse(result.passed());
		MatcherAssert.assertThat(result.problem(), Matchers.containsString("compile"));
	}

	@Test
	public void testRuleTesterReportsAFilterThatFailsToEvaluate() {
		// The binary keeps a finding whose filter errors and only warns, which would silently
		// make the filter a no-op; the author has to hear about it.
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule = customRule();
		rule.setFilter("finding[\"secret\"].startsWith(\"tlk_int_Q7\")");

		BetterleaksRuleTestResult result = engine.testRule(rule);

		Assertions.assertFalse(result.passed());
		MatcherAssert.assertThat(result.problem(), Matchers.containsString("filter"));
	}

	/** Synthetic internal-token format; split so no scanner flags this file. */
	private static final String CUSTOM_TOKEN = "tlk_int_" + "Q7m2Zp9Xc4Vb8Nn1";

	private static com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto customRule() {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto rule =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		rule.setPositiveSample("key = " + CUSTOM_TOKEN);
		rule.setNegativeSample("key = tlk_int_short");
		return rule;
	}

	@Test
	public void testCleanTreeHasNoFindings() throws Exception {
		writeFixture("src/App.java", "class App {}\n");

		Assertions.assertEquals(List.of(), engine.scan(target, List.of("github-pat")));
	}

	@Test
	public void testValidateOfARuleWithoutAProviderCheckIsUnverifiableAndStaysRedacted()
			throws Exception {
		// generic-password has no `validate` block, so nothing leaves the machine.
		String password = "hunter2" + "Zx9Qw8Er7Ty6";
		writeFixture("window.txt", "a\npassword = \"" + password + "\"\nb\n");

		List<BetterleaksValidation> validations = engine.validate(target, "generic-password");

		Assertions.assertEquals(List.of(
				new BetterleaksValidation("generic-password", "window.txt", 2, null)),
				validations);
		Assertions.assertEquals(
				com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus.UNVERIFIABLE,
				validations.get(0).toStatus());
		MatcherAssert.assertThat(lastResult.get().stdout(),
				Matchers.not(Matchers.containsString(password)));
	}

	@Test
	public void testRuleUnknownToTheBinaryFailsTheScanLoudly() {
		// A pinned rule list that drifted from the installed binary must not silently scan less.
		Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("no-such-rule")));
	}
}

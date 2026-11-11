package com.tracelink.appsec.module.betterleaks.engine;

import java.util.Arrays;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BetterleaksReportParserTest {

	/** Synthetic, split so that no secrets scanner flags this source file. */
	private static final String FAKE_SECRET = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	/** Shape of a real betterleaks 1.8.1 JSON finding, trimmed. */
	private static String finding(String ruleId, String file, int line, String secret) {
		return "{\"RuleID\":\"" + ruleId + "\",\"Description\":\"d\",\"StartLine\":" + line
				+ ",\"EndLine\":" + line + ",\"StartColumn\":9,\"EndColumn\":48,"
				+ "\"Match\":\"token: " + secret + "\",\"Secret\":\"" + secret + "\","
				+ "\"Attributes\":{\"confidence\":\"high\",\"path\":\"" + file + "\"},"
				+ "\"Tags\":[],\"Fingerprint\":\"" + file + ":" + ruleId + ":" + line + "\","
				+ "\"File\":\"" + file + "\",\"Entropy\":4.88,\"ValidationStatus\":\"invalid\"}";
	}

	private final BetterleaksReportParser parser = new BetterleaksReportParser();

	@Test
	public void testParsesRuleFileAndLine() throws Exception {
		String json = "[" + finding("github-pat", "/w/test/Fixture.java", 3, "REDACTED") + ","
				+ finding("aws-access-token", "/w/src/app.properties", 2, "REDACTED") + "]";

		List<BetterleaksFinding> findings = parser.parse(json);

		Assertions.assertEquals(List.of(
				new BetterleaksFinding("github-pat", "/w/test/Fixture.java", 3),
				new BetterleaksFinding("aws-access-token", "/w/src/app.properties", 2)),
				findings);
	}

	@Test
	public void testParsesValidationStatusAndTreatsItsAbsenceAsNone() throws Exception {
		String unvalidated = "{\"RuleID\":\"generic-password\",\"StartLine\":2,"
				+ "\"File\":\"a.txt\",\"Secret\":\"REDACTED\"}";
		String json = "[" + finding("github-pat", "a.txt", 1, "REDACTED") + "," + unvalidated
				+ "]";

		List<BetterleaksValidation> validations = parser.parseValidations(json);

		Assertions.assertEquals(List.of(
				new BetterleaksValidation("github-pat", "a.txt", 1, "invalid"),
				new BetterleaksValidation("generic-password", "a.txt", 2, null)), validations);
		Assertions.assertEquals(List.of(), parser.parseValidations("null"));
	}

	@Test
	public void testCleanScanPrintsNullAndMeansNoFindings() throws Exception {
		// betterleaks prints the literal "null" rather than [] when nothing is found.
		Assertions.assertEquals(List.of(), parser.parse("null\n"));
		Assertions.assertEquals(List.of(), parser.parse("[]"));
		Assertions.assertEquals(List.of(), parser.parse("  "));
	}

	@Test
	public void testMalformedOutputIsAScanFailure() {
		BetterleaksScanException e = Assertions.assertThrows(BetterleaksScanException.class,
				() -> parser.parse("[{\"RuleID\":\"x\""));
		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("unreadable"));
	}

	@Test
	public void testAFindingWithoutARuleOrFileIsAScanFailure() {
		Assertions.assertThrows(BetterleaksScanException.class,
				() -> parser.parse("[{\"File\":\"/w/a.txt\",\"StartLine\":1}]"));
		Assertions.assertThrows(BetterleaksScanException.class,
				() -> parser.parse("[{\"RuleID\":\"github-pat\",\"StartLine\":1}]"));
	}

	@Test
	public void testNeverRetainsTheMatchOrSecretEvenIfTheBinaryLeaksIt() throws Exception {
		// Defence in depth: the engine always passes --redact, but if a future binary ignored
		// it, the parsed model still has nowhere to put the secret.
		List<BetterleaksFinding> findings =
				parser.parse("[" + finding("github-pat", "/w/a.java", 1, FAKE_SECRET) + "]");

		MatcherAssert.assertThat(findings.toString(),
				Matchers.not(Matchers.containsString(FAKE_SECRET)));
		MatcherAssert.assertThat(Arrays.stream(BetterleaksFinding.class.getRecordComponents())
				.map(component -> component.getName().toLowerCase()).toList(),
				Matchers.everyItem(Matchers.not(Matchers.anyOf(
						Matchers.containsString("secret"), Matchers.containsString("match")))));
	}

	@Test
	public void testParseFailureMessageNeverEchoesTheOutput() {
		String leaky = "[{\"RuleID\":\"x\",\"Secret\":\"" + FAKE_SECRET + "\"";

		BetterleaksScanException e =
				Assertions.assertThrows(BetterleaksScanException.class, () -> parser.parse(leaky));

		MatcherAssert.assertThat(e.getMessage(), Matchers.not(Matchers.containsString(FAKE_SECRET)));
		Assertions.assertNull(e.getCause(),
				"the JSON library's exception quotes the input, so it must not be kept as the cause");
	}
}

package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ScannerFailureReasonTest {

	@Test
	public void nothingToSayWithoutErrors() {
		Assertions.assertNull(ScannerFailureReason.summarize(List.of(), false));
		Assertions.assertNull(ScannerFailureReason.summarize(null, false));
	}

	@Test
	public void aParseErrorNamesTheFileAndTheKindOfError() {
		String reason = ScannerFailureReason.summarize(List.of(
				"In File '/tmp/reposcan-2514876325729380615438/regex/clean.java' Error: LexException: Lexical error in file at line 1, column 1: \"#\" (35)"),
				false);

		Assertions.assertEquals("1 problem: regex/clean.java (LexException)", reason);
	}

	@Test
	public void textQuotedFromTheCodeIsCutOff() {
		String reason = ScannerFailureReason.summarize(
				List.of("Parsing error: Unexpected keyword 'var' near password = \"hunter2\""), false);

		Assertions.assertEquals("1 problem: Parsing error: Unexpected keyword", reason);
		Assertions.assertFalse(reason.contains("hunter2"));
	}

	@Test
	public void ourOwnParseMessagesAreKept() {
		String reason = ScannerFailureReason.summarize(List.of("Could not parse the file malformed.yaml as YAML",
				"Could not parse the file malformed.json as JSON"), false);

		Assertions.assertEquals("2 problems: Could not parse the file malformed.yaml as YAML;"
				+ " Could not parse the file malformed.json as JSON", reason);
	}

	@Test
	public void onlyTheFirstThreeDistinctProblemsAreNamed() {
		String reason = ScannerFailureReason.summarize(List.of("a", "b", "b", "c", "d", "e"), false);

		Assertions.assertEquals("6 problems: a; b; c; and 2 more", reason);
	}

	@Test
	public void aSecretsScannerGetsOnlyACount() {
		String reason = ScannerFailureReason.summarize(List.of("token ghp_abcdef failed"), true);

		Assertions.assertEquals("1 problem (details are not shown for a secrets scanner)", reason);
	}

	@Test
	public void aLongMessageIsShortened() {
		String reason = ScannerFailureReason.summarize(List.of("x".repeat(400)), false);

		Assertions.assertTrue(reason.length() < 120, reason);
		Assertions.assertTrue(reason.endsWith("…"));
	}
}

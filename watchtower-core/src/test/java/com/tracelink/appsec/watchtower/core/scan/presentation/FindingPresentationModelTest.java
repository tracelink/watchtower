package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultViolation;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

class FindingPresentationModelTest {

	@Test
	void unresolvedHistoricalPmdMessagesKeepOriginalEvidenceWithoutInventedNames() {
		for (String rule : List.of("ImmutableField", "UnusedPrivateField")) {
			var violation = new PRScanResultViolation();
			violation.setViolationName(rule);
			violation.setMessage("The field {0} needs review.");
			var finding = FindingPresentationModel.fromPullRequest(List.of(violation)).getFirst();
			assertTrue(finding.hasUnresolvedMessage());
			assertFalse(finding.getGuidance().contains("{0}"));
			assertEquals(violation.getMessage(), finding.getOriginalGuidance());
			assertEquals("The field {0} needs review.", violation.getMessage());
			violation.setMessage("The field settings can be final.");
			finding = FindingPresentationModel.fromPullRequest(List.of(violation)).getFirst();
			assertFalse(finding.hasUnresolvedMessage());
			assertEquals(violation.getMessage(), finding.getGuidance());
		}
	}

	@Test
	void mapsPullRequestFindingWithRuleDocumentation() {
		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setViolationName("Unsafe deserialization");
		violation.setSeverity("High");
		violation.setSeverityValue(1);
		violation.setFileName("src/App.java");
		violation.setLineNumber(42);
		violation.setMessage("Use an allowlist.");
		violation.setExternalUrl("https://example.invalid/rules/deserialization");

		FindingPresentationModel finding =
				FindingPresentationModel.fromPullRequest(List.of(violation)).get(0);

		assertEquals("src/App.java:42", finding.getLocation());
		assertEquals("Use an allowlist.", finding.getGuidance());
		assertTrue(finding.hasSourceAction());
		assertTrue(finding.hasExternalUrl());
	}

	@Test
	void aFindingOfARuleThatChangedOrWasDeletedSaysSoInAChipWithAHover() {
		// Dev E2E G03: an old report showed the rule's current guidance as if it were what the rule said at the scan.
		UploadScanResultViolation changed = new UploadScanResultViolation();
		changed.setViolationName("Rule");
		changed.setRuleChange(com.tracelink.appsec.watchtower.core.rule.RuleChange.CHANGED);
		UploadScanResultViolation deleted = new UploadScanResultViolation();
		deleted.setViolationName("Gone rule");
		deleted.setRuleChange(com.tracelink.appsec.watchtower.core.rule.RuleChange.DELETED);
		UploadScanResultViolation plain = new UploadScanResultViolation();
		plain.setViolationName("Plain rule");

		var findings = FindingPresentationModel.fromUpload(List.of(changed, deleted, plain));

		org.junit.jupiter.api.Assertions.assertEquals("Rule changed", findings.get(0).getRuleChangeLabel());
		org.junit.jupiter.api.Assertions.assertTrue(findings.get(0).getRuleChangeTip().contains("edited after this scan"));
		org.junit.jupiter.api.Assertions.assertEquals("Rule deleted", findings.get(1).getRuleChangeLabel());
		org.junit.jupiter.api.Assertions.assertTrue(findings.get(1).getRuleChangeTip().contains("no longer exists"));
		org.junit.jupiter.api.Assertions.assertNull(findings.get(2).getRuleChangeLabel());
		org.junit.jupiter.api.Assertions.assertNull(findings.get(2).getRuleChangeTip());
	}

	@Test
	void mapsUploadAndImageSpecificDetails() {
		UploadScanResultViolation upload = new UploadScanResultViolation();
		upload.setViolationName("Secret");
		upload.setFileName("config.yml");
		upload.setLineNumber(7);
		upload.setSeverity("Elevated");
		upload.setSeverityValue(2);

		ImageScanResultViolation image = new ImageScanResultViolation();
		image.setViolationName("CVE-2026-0001");
		image.setPackageName("openssl");
		image.setSeverity("High");
		image.setSeverityValue(1);
		image.setScore("9.8");
		image.setVector("CVSS:3.1/AV:N/AC:L");

		FindingPresentationModel uploadFinding =
				FindingPresentationModel.fromUpload(List.of(upload)).get(0);
		FindingPresentationModel imageFinding =
				FindingPresentationModel.fromImage(List.of(image)).get(0);

		assertEquals("File", uploadFinding.getLocationType());
		assertFalse(uploadFinding.hasSourceAction());
		assertFalse(uploadFinding.hasCvss());
		assertEquals("Package", imageFinding.getLocationType());
		assertEquals("openssl", imageFinding.getLocation());
		assertTrue(imageFinding.hasCvss());
	}

	@Test
	void imageFindingsShowTheAdvisoryOnceWithItsCvss() {
		ImageScanResultViolation image = new ImageScanResultViolation();
		image.setViolationName("CVE-2012-0881 - xerces:xercesImpl");
		image.setPackageName("xerces:xercesImpl");
		image.setScore("N/A");
		ImageScanResultViolation named = new ImageScanResultViolation();
		named.setViolationName("Weak hashing in openssl");
		named.setPackageName("openssl");
		named.setScore("5.0");
		named.setVector("AV:N/AC:L/Au:N/C:N/I:N/A:P");

		List<FindingPresentationModel> findings = FindingPresentationModel.fromImage(List.of(image, named));

		assertEquals("CVE-2012-0881", findings.get(0).getTitle());
		assertEquals("No CVSS", findings.get(0).getCvss().shortLabel());
		assertEquals("Weak hashing in openssl", findings.get(1).getTitle());
		assertEquals("CVSS 5.0 · Medium", findings.get(1).getCvss().label());
		assertEquals("Network · No auth · Availability", findings.get(1).getCvss().vectorText());
		assertEquals("Advisory", findings.get(1).getExternalUrlLabel());
	}

	@Test
	void codeFindingsHaveNoCvss() {
		UploadScanResultViolation upload = new UploadScanResultViolation();
		upload.setViolationName("Rule");
		assertNull(FindingPresentationModel.fromUpload(List.of(upload)).get(0).getCvss());
	}

	@Test
	void nullListsProduceAnEmptyWorkspace() {
		assertTrue(FindingPresentationModel.fromPullRequest(null).isEmpty());
		assertTrue(FindingPresentationModel.fromUpload(null).isEmpty());
		assertTrue(FindingPresentationModel.fromImage(null).isEmpty());
	}

	@Test
	void carriesLiveVerificationOnlyWhereOneApplies() {
		PRScanResultViolation secret = new PRScanResultViolation();
		secret.setViolationName("Betterleaks: github-pat");
		secret.setViolationId(7L);
		PRScanResultViolation other = new PRScanResultViolation();
		other.setViolationName("Regex: something");
		other.setViolationId(8L);

		List<FindingPresentationModel> findings = FindingPresentationModel.fromPullRequest(
				List.of(secret, other), violation -> violation.getViolationId() == 7L
						? new FindingVerification(7L, LiveVerificationStatus.LIVE, true)
						: null);

		assertTrue(findings.get(0).hasVerification());
		assertEquals(7L, findings.get(0).getVerification().violationId());
		assertEquals("Live - rotate now", findings.get(0).getVerification().statusLabel());
		assertFalse(findings.get(1).hasVerification());
		assertFalse(FindingPresentationModel.fromPullRequest(List.of(secret)).get(0)
				.hasVerification());
	}

	@Test
	void anUnrequestedVerificationHasNoStatusLabel() {
		FindingVerification verification = new FindingVerification(7L, null, false);

		assertEquals("", verification.statusLabel());
		assertEquals("", verification.statusKey());
	}

	@Test
	void rejectsUnsafeDocumentationSchemes() {
		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setExternalUrl("javascript:alert(1)");

		FindingPresentationModel finding =
				FindingPresentationModel.fromPullRequest(List.of(violation)).get(0);

		assertFalse(finding.hasExternalUrl());
	}

	@Test
	void carriesAModuleActionForAFinding() {
		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setViolationName("Betterleaks: aws-access-token");
		FindingAction action = new FindingAction("Allowlist…", "/betterleaks/allowlist?rule=x");

		FindingPresentationModel finding = FindingPresentationModel
				.fromPullRequest(List.of(violation), v -> null, v -> action).get(0);

		assertTrue(finding.hasAction());
		assertEquals(action, finding.getAction());
	}

	@Test
	void hasNoActionByDefault() {
		FindingPresentationModel finding = FindingPresentationModel
				.fromPullRequest(List.of(new PRScanResultViolation())).get(0);

		assertFalse(finding.hasAction());
	}

	@Test
	void actionUrlsMustStayOnWatchtower() {
		for (String url : new String[] {"https://evil.example/x", "//evil.example/x",
				"javascript:alert(1)", "", "/\\evil.example"}) {
			org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
					() -> new FindingAction("Go", url), url);
		}
		assertEquals("/a?b=c", new FindingAction("Go", "/a?b=c").url());
	}
}

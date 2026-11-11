package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;

import jakarta.persistence.EntityManager;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;

/** Exercises the Flyway columns and JPA mapping through an actual flush and reload. */
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
class CodeScanMetadataPersistenceTest {
	@Autowired EntityManager entities;
	private final RuleExecutionIdentity identity = new RuleExecutionIdentity(999999L, "regex",
			"a".repeat(64), "external-key", "upstream-key");

	private String snapshot() {
		return CodeScanExecutionSnapshotCodec.encode(new CodeScanExecutionSnapshot(1, 99L,
				"original policy", RulePriority.MEDIUM, List.of(), List.of(), null));
	}

	private CodeScanViolation violation() {
		CodeScanViolation violation = new CodeScanViolation();
		violation.setViolationName("Original display name");
		violation.setFileName("/tmp/source/File.java");
		violation.setLineNum(5);
		violation.setSeverity(RulePriority.HIGH);
		violation.setRuleIdentity(identity);
		violation.setEffectiveBlocking(true);
		violation.setEngineFingerprint("b".repeat(64));
		violation.setMessage("transient message");
		return violation;
	}

	private PullRequestScanEntity prScan() {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		container.setApiLabel("metadata-test");
		container.setAuthor("tester");
		container.setSourceBranch("feature");
		container.setRepoName("example");
		container.setPrId("1");
		entities.persist(container);
		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(container);
		scan.setStatus(ScanStatus.DONE);
		entities.persist(scan);
		return scan;
	}

	@Test void prFindingKeepsOriginalPolicyWhenBypassedAndIdentityWithoutALiveRule() {
		PullRequestScanEntity scan = prScan();
		scan.setExecutionSnapshotJson(snapshot());
		PullRequestViolationEntity finding = new PullRequestViolationEntity(violation(), Path.of("/tmp/source"));
		finding.setScan(scan);
		finding.setNewViolation(true);
		finding.setBlocking(false);
		finding.setBypassed(true);
		entities.persist(finding);
		entities.flush();
		entities.clear();
		var reloaded = entities.find(PullRequestViolationEntity.class, finding.getId());
		assertEquals(identity, reloaded.getRuleIdentity());
		assertEquals("b".repeat(64), reloaded.getEngineFingerprint());
		assertEquals(Boolean.TRUE, reloaded.getEffectiveBlocking());
		assertEquals(Boolean.FALSE, reloaded.getFinalBlocking());
		assertEquals(Boolean.TRUE, reloaded.getNewFinding());
		assertTrue(reloaded.isBypassed());
		assertNull(reloaded.getMessage());
		assertEquals("File.java", reloaded.getFileName());
		assertEquals(snapshot(), reloaded.getScan().getExecutionSnapshotJson());
	}

	@Test void uploadFindingAndSnapshotRoundTrip() {
		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setName("example.zip");
		container.setSubmitter("tester");
		container.setTicket("metadata-test");
		container.setRuleSet("original policy");
		container.setStorageKey("example.zip");
		entities.persist(container);
		UploadScanEntity scan = new UploadScanEntity();
		scan.setContainer(container);
		scan.setStatus(ScanStatus.DONE);
		scan.setExecutionSnapshotJson(snapshot());
		entities.persist(scan);
		UploadViolationEntity finding = new UploadViolationEntity(violation(), Path.of("/tmp/source"));
		finding.setScan(scan);
		entities.persist(finding);
		entities.flush();
		entities.clear();
		var reloaded = entities.find(UploadViolationEntity.class, finding.getId());
		assertEquals(identity, reloaded.getRuleIdentity());
		assertEquals(Boolean.TRUE, reloaded.getEffectiveBlocking());
		assertEquals(Boolean.TRUE, reloaded.getFinalBlocking());
		assertNull(reloaded.getNewFinding(), "uploads have no cross-scan new-finding baseline");
		assertEquals(snapshot(), reloaded.getScan().getExecutionSnapshotJson());
	}

	@Test void legacyFindingsRetainUnknownPolicyAndIdentity() {
		var violation = violation();
		violation.setRuleIdentity(null);
		violation.setEngineFingerprint(null);
		violation.setEffectiveBlocking(null);
		var finding = new PullRequestViolationEntity(violation, Path.of("/tmp/source"));
		finding.setScan(prScan());
		entities.persist(finding);
		entities.flush();
		entities.clear();
		var reloaded = entities.find(PullRequestViolationEntity.class, finding.getId());
		assertNull(reloaded.getRuleIdentity());
		assertNull(reloaded.getEffectiveBlocking());
		assertNull(reloaded.getFinalBlocking());
		assertNull(reloaded.getNewFinding());
		assertNull(reloaded.getEngineFingerprint());
		assertNull(reloaded.getScan().getExecutionSnapshotJson());
	}
}

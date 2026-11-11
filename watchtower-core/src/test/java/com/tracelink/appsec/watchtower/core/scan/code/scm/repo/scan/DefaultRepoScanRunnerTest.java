package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.springframework.context.ApplicationEventPublisher;

import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkerIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportStore;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

public class DefaultRepoScanRunnerTest {
	static class Definition extends MockCustomRuleDto {
		@Override protected RuleRevision executableDefinition() {
			return RuleRevision.definition("test", "v1").field("pattern", "example");
		}
	}

	private RepoScanRepository scans;

	private RepoReportStore store;

	private IScmApi api;

	private RulesetEntity ruleset;

	private RepoScanEntity scan;

	private DefaultRepoScanRunner runner;
	private ScanRegistrationService registry;

	@BeforeEach
	public void setup() {
		scans = BDDMockito.mock(RepoScanRepository.class);
		store = BDDMockito.mock(RepoReportStore.class);
		api = BDDMockito.mock(IScmApi.class);
		ApiIntegrationEntity integration = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integration.createApi()).thenReturn(api);
		ApiIntegrationService integrations = BDDMockito.mock(ApiIntegrationService.class);
		BDDMockito.when(integrations.findByLabel("bb")).thenReturn(integration);
		registry = BDDMockito.mock(ScanRegistrationService.class);
		BDDMockito.when(registry.getCodeScanners())
				.thenReturn(List.of(BDDMockito.mock(ICodeScanner.class)));
		ruleset = BDDMockito.mock(RulesetEntity.class);
		RulesetDto dto = new RulesetDto();
		dto.setName("Default");
		BDDMockito.when(ruleset.toDto()).thenReturn(dto);
		BDDMockito.when(ruleset.getName()).thenReturn("Default");

		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("payments-api");
		repo.setRuleset(ruleset);
		scan = new RepoScanEntity();
		org.springframework.test.util.ReflectionTestUtils.setField(scan, "id", 17L);
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setPlanId(1);
		scan.setStatus(ScanStatus.IN_PROGRESS);
		scan.setAttempts(1);
		BDDMockito.when(scans.claim(ArgumentMatchers.anyLong(), ArgumentMatchers.anyString(),
				ArgumentMatchers.anyLong(), ArgumentMatchers.anyLong(), ArgumentMatchers.any(),
				ArgumentMatchers.any())).thenReturn(1);
		BDDMockito.when(scans.findWithRepository(ArgumentMatchers.anyLong()))
				.thenReturn(Optional.of(scan));

		runner = new DefaultRepoScanRunner(scans, BDDMockito.mock(RepoScanPlanRepository.class),
				integrations, BDDMockito.mock(RulesetService.class), registry, store,
				new RepoScanReportWriter(store, 20), BDDMockito.mock(RepoCatalogDao.class),
				BDDMockito.mock(MetricsProjectionWriter.class),
				BDDMockito.mock(ApplicationEventPublisher.class), new WorkerIdentity(), 1);
	}

	@Test
		public void localRepositoryScanDoesNotWaitForTheAwsReview() throws IOException {
		var remote = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.class);
		org.springframework.test.util.ReflectionTestUtils.setField(runner, "remoteAssessments", remote);
		BDDMockito.when(remote.selected(ArgumentMatchers.any())).thenReturn(true);
		BDDMockito.when(remote.prepareRepository(ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn("saved-run");
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
			runner.run(17);
			Assertions.assertEquals(ScanStatus.DONE, scan.getStatus());
			BDDMockito.verify(remote, BDDMockito.never()).cancelRepository(ArgumentMatchers.anyString());
			BDDMockito.verify(store).put(ArgumentMatchers.anyString(), ArgumentMatchers.any(), ArgumentMatchers.anyString());
	}

	@Test
	public void ordinaryRepositoryFailureStillCancelsItsAwsRun() throws IOException {
		var remote = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.class);
		org.springframework.test.util.ReflectionTestUtils.setField(runner, "remoteAssessments", remote);
		BDDMockito.when(remote.selected(ArgumentMatchers.any())).thenReturn(true);
		BDDMockito.when(remote.prepareRepository(ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn("saved-run");
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
		BDDMockito.doThrow(new IOException("Source unavailable")).when(api).downloadSource(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.any());
		runner.run(17);
		Assertions.assertEquals(ScanStatus.FAILED, scan.getStatus());
		BDDMockito.verify(remote).cancelRepository("saved-run");
	}

	@Test
	public void aMissingBranchFinishesWithoutScanning() {
		BDDMockito.when(api.getBranch("payments-api", "main")).thenReturn(Optional.empty());

		Assertions.assertFalse(runner.run(1).retry());

		Assertions.assertEquals(ScanStatus.DONE, scan.getStatus());
		Assertions.assertEquals(RepoScanOutcome.BRANCH_MISSING, scan.getOutcome());
		Assertions.assertEquals("Default", scan.getRulesetName());
	}

	@Test
	public void aTooLargeRepositoryIsSkipped() {
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
		scan.getRepository().setSizeBytes(2L * 1024 * 1024);

		runner.run(1);

		Assertions.assertEquals(RepoScanOutcome.SKIPPED_SIZE, scan.getOutcome());
		Assertions.assertEquals("abc", scan.getCommitHash());
		Assertions.assertEquals(5, scan.getCommitDate());
	}

	@Test
	public void anUnchangedBranchReusesThePreviousReport() throws IOException {
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
		RepoScanEntity previous = new RepoScanEntity();
		org.springframework.test.util.ReflectionTestUtils.setField(previous, "id", 16L);
		previous.setCommitHash("abc");
		Definition rule = new Definition();
		rule.setId(42L);
		rule.setName("rule");
		rule.setPriority(RulePriority.HIGH);
		ruleset.toDto().setRules(java.util.Set.of(rule));
		ruleset.toDto().setBlockingLevel(RulePriority.HIGH);
		ICodeScanner scanner = registry.getCodeScanners().iterator().next();
		BDDMockito.when(scanner.getSupportedRuleClass()).thenReturn(List.of(Definition.class));
		BDDMockito.when(scanner.getExecutionIdentity(ArgumentMatchers.any()))
				.thenReturn(new EngineExecutionIdentity("test", "1", "b".repeat(64), true));
		CodeScanExecutionSnapshot snapshot = CodeScanExecutionSnapshot.capture(ruleset.toDto(),
				registry.getCodeScanners(), new CodeScanConfig()).withOutcome(scanner, "RAN");
		previous.setRulesetFingerprint(snapshot.fingerprint());
		previous.setReportKey("reports/old.json.gz");
		previous.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH)));
		RepoScanReport.Finding finding = new RepoScanReport.Finding("rule", "High", "App.java", 1,
				"message", "fingerprint", true, false, rule.getExecutionIdentity(),
				snapshot.engineKey(scanner.getClass().getName()), true, "old-key");
		RepoScanReport stored = new RepoScanReport(RepoScanReport.SCHEMA, previous.getId(), "bb",
				"payments-api", "main", "abc", "Default", List.of(finding), List.of(), List.of(), 1, snapshot).withComparison(RepoScanReport.REPOSITORY_SCOPE,null);
		BDDMockito.when(store.get(previous.getReportKey())).thenReturn(Optional.of(RepoReportCodec.encode(stored)));
		BDDMockito.when(scans.findFirstByRepositoryIdAndBranchAndStatusAndIdNotOrderByEndDateDesc(
				ArgumentMatchers.anyLong(), ArgumentMatchers.eq("main"),
				ArgumentMatchers.eq(ScanStatus.DONE), ArgumentMatchers.anyLong()))
				.thenReturn(Optional.of(previous));

		runner.run(1);

		Assertions.assertEquals(RepoScanOutcome.UNCHANGED, scan.getOutcome());
		Assertions.assertEquals(1, scan.getFindingCount());
		Assertions.assertEquals(0, scan.getNewCount());
		var bytes = org.mockito.ArgumentCaptor.forClass(byte[].class);
		BDDMockito.verify(store).put(ArgumentMatchers.startsWith("reports/repository/bb/payments-api/"),
				bytes.capture(), ArgumentMatchers.eq(RepoReportCodec.CONTENT_TYPE));
		var reused = RepoReportCodec.decode(bytes.getValue());
		Assertions.assertEquals(scan.getId(), reused.scanId());
		Assertions.assertEquals(previous.getId(), reused.executionSnapshot().reusedFromScanId());
		Assertions.assertFalse(reused.findings().getFirst().isNew());
		Assertions.assertNotEquals("old-key", reused.findings().getFirst().findingKey());
		Assertions.assertEquals(0, scan.getRulesEvaluated());
		Assertions.assertEquals(reused.executionSnapshot(),
				CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson()));
		BDDMockito.verify(api, BDDMockito.never()).downloadSource(ArgumentMatchers.anyString(),
				ArgumentMatchers.anyString(), ArgumentMatchers.any());
	}

	@Test
	public void legacyOrPartialReportsAreScannedAgainEvenWhenTheStoredFingerprintMatches() throws IOException {
		CodeScanExecutionSnapshot snapshot = CodeScanExecutionSnapshot.capture(ruleset.toDto(),
				registry.getCodeScanners(), new CodeScanConfig());
		for (RepoScanReport report : List.of(
				new RepoScanReport(1, 0, "bb", "payments-api", "main", "abc", "Default",
						List.of(), List.of(), List.of(), 0),
				new RepoScanReport(RepoScanReport.SCHEMA, 0, "bb", "payments-api", "main", "abc", "Default",
						List.of(), List.of(), List.of("partial scanner error"), 0, snapshot),
				new RepoScanReport(RepoScanReport.SCHEMA + 1, 0, "bb", "payments-api", "main", "abc", "Default",
						List.of(), List.of(), List.of(), 0, snapshot),
				new RepoScanReport(RepoScanReport.SCHEMA, 0, "bb", "payments-api", "main", "abc", "Default",
						List.of(new RepoScanReport.Finding("unknown", "High", "App.java", 1,
								"message", "fingerprint", false, false)), List.of(), List.of(), 1, snapshot),
				new RepoScanReport(RepoScanReport.SCHEMA, 0, "bb", "payments-api", "main", "abc", "Default",
						List.of(), List.of(), List.of(), 1, snapshot),
				new RepoScanReport(RepoScanReport.SCHEMA, 0, "bb", "payments-api", "main", "wrong-commit", "Default",
						List.of(), List.of(), List.of(), 0, snapshot))) {
			RepoScanEntity previous = new RepoScanEntity();
			previous.setCommitHash("abc");
			previous.setRulesetFingerprint(snapshot.fingerprint());
			previous.setReportKey("reports/old.json.gz");
			BDDMockito.when(store.get(previous.getReportKey())).thenReturn(Optional.of(RepoReportCodec.encode(report)));
			BDDMockito.when(api.getBranch("payments-api", "main"))
					.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
			BDDMockito.when(scans.findFirstByRepositoryIdAndBranchAndStatusAndIdNotOrderByEndDateDesc(
					ArgumentMatchers.anyLong(), ArgumentMatchers.eq("main"),
					ArgumentMatchers.eq(ScanStatus.DONE), ArgumentMatchers.anyLong()))
					.thenReturn(Optional.of(previous));
			runner.run(1);
			Assertions.assertEquals(RepoScanOutcome.SCANNED, scan.getOutcome());
		}
		BDDMockito.verify(api, BDDMockito.times(6)).downloadSource(ArgumentMatchers.eq("payments-api"),
				ArgumentMatchers.eq("abc"), ArgumentMatchers.any());
	}

	@Test
	public void aThrowingScannerPersistsFailureEvidenceWithoutClaimingSuccessfulEvaluation() {
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("rule");
		rule.setId(1L);
		rule.setPriority(RulePriority.HIGH);
		ruleset.toDto().setRules(java.util.Set.of(rule));
		ICodeScanner scanner = registry.getCodeScanners().iterator().next();
		BDDMockito.when(scanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		BDDMockito.when(scanner.scan(ArgumentMatchers.any()))
				.thenThrow(new IllegalStateException("engine failure"));
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenReturn(Optional.of(new ScmBranch("main", "abc", 5)));
		runner.run(1);
		Assertions.assertEquals(ScanStatus.FAILED, scan.getStatus());
		var snapshot = CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson());
		Assertions.assertEquals("FAILED", snapshot.engines().getFirst().status());
		Assertions.assertEquals("FAILED", snapshot.rules().getFirst().coverage());
		Assertions.assertNull(snapshot.rules().getFirst().evaluatedOpportunities());
		Assertions.assertFalse(snapshot.isReusable());
	}

	@Test
	public void aRateLimitPutsTheScanBackForLater() {
		BDDMockito.when(api.getBranch("payments-api", "main"))
				.thenThrow(new RateLimitedException(120));

		WorkOutcome outcome = runner.run(1);

		Assertions.assertTrue(outcome.retry());
		Assertions.assertEquals(120, outcome.delaySeconds());
		Assertions.assertEquals(ScanStatus.NOT_STARTED, scan.getStatus());
	}

	@Test
	public void tooManyAttemptsFailTheScan() {
		scan.setAttempts(DefaultRepoScanRunner.MAX_ATTEMPTS + 1);

		runner.run(1);

		Assertions.assertEquals(ScanStatus.FAILED, scan.getStatus());
		Assertions.assertTrue(scan.getError().startsWith("Stopped after"));
	}

	@Test
	public void aScanOwnedByAnotherPodIsRetriedAndAFinishedOneDropped() {
		BDDMockito.when(scans.claim(ArgumentMatchers.anyLong(), ArgumentMatchers.anyString(),
				ArgumentMatchers.anyLong(), ArgumentMatchers.anyLong(), ArgumentMatchers.any(),
				ArgumentMatchers.any())).thenReturn(0);
		BDDMockito.when(scans.findById(1L)).thenReturn(Optional.of(scan));
		Assertions.assertTrue(runner.run(1).retry());

		scan.setStatus(ScanStatus.DONE);
		Assertions.assertFalse(runner.run(1).retry());
	}
}

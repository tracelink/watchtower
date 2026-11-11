package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleChange;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeLine;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

@ExtendWith(SpringExtension.class)
public class PRScanResultServiceTest {

	private PRScanResultService scanResultService;

	@MockitoBean
	private PRContainerRepository mockPrRepo;

	@MockitoBean
	private PRScanRepository mockScanRepo;

	@MockitoBean
	private PRViolationRepository mockVioRepo;

	@MockitoBean
	private RepositoryRepository mockRepoRepo;

	@MockitoBean
	private RuleService mockRuleService;

	@MockitoBean
	private ApiIntegrationService mockApiService;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(PRScanResultService.class);

	private static final String SENSITIVE_MODULE = "Secrets";

	private static final String FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE";

	private ApplicationEventPublisher mockEventPublisher;

	@BeforeEach
	public void setup() throws Exception {
		ScanRegistrationService scanRegistrationService = new ScanRegistrationService();
		ICodeScanner sensitiveScanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.when(sensitiveScanner.isSensitive()).thenReturn(true);
		scanRegistrationService.registerScanner(SENSITIVE_MODULE, sensitiveScanner);
		mockEventPublisher = BDDMockito.mock(ApplicationEventPublisher.class);
		this.scanResultService =
				new PRScanResultService(mockPrRepo, mockRepoRepo, mockScanRepo, mockVioRepo,
						mockRuleService, mockApiService, scanRegistrationService,
						mockEventPublisher);
	}

	@Test
	public void testSavePublishesScanCompletedEventWithAFindingsSnapshot() {
		PullRequestViolationEntity ve = makeMockVioEntity("Secret rule", true,
				"config/app.properties", 12, RulePriority.HIGH, true);
		BDDMockito.when(ve.getId()).thenReturn(77L);
		PullRequest mockPR = stubSavePersistence(1337L);

		long scanId = saveScan(mockPR, ve);

		org.mockito.ArgumentCaptor<PRScanCompletedEvent> eventCaptor =
				org.mockito.ArgumentCaptor.forClass(PRScanCompletedEvent.class);
		BDDMockito.verify(mockEventPublisher).publishEvent(eventCaptor.capture());
		PRScanCompletedEvent event = eventCaptor.getValue();
		Assertions.assertEquals(1337L, scanId);
		Assertions.assertEquals(1337L, event.scanId());
		Assertions.assertSame(mockPR, event.pullRequest());
		Assertions.assertEquals(List.of(new PRScanCompletedEvent.Finding(77L, "Secret rule",
				RulePriority.HIGH, "config/app.properties", 12, true, true)), event.findings());
	}

	@Test
	public void testSaveSucceedsEvenWhenAScanCompletedListenerThrows() {
		// A listener runs on the scan thread unless it is async. Its failure must never fail
		// the scan - SQS would redeliver it and the scan would be saved twice.
		PullRequestViolationEntity ve = makeMockVioEntity("rule", false, "App.java", 1,
				RulePriority.LOW, true);
		PullRequest mockPR = stubSavePersistence(42L);
		BDDMockito.doThrow(new IllegalStateException("listener down")).when(mockEventPublisher)
				.publishEvent(BDDMockito.any(Object.class));

		Assertions.assertEquals(42L, saveScan(mockPR, ve));
	}

	@Test
	public void testSaveWithoutViolationsPublishesNoEvent() {
		scanResultService.savePullRequestScan(BDDMockito.mock(PullRequest.class), 0, null,
				new ArrayList<>(), 0L, null);

		BDDMockito.verifyNoInteractions(mockEventPublisher);
	}

	private PullRequest stubSavePersistence(long scanEntityId) {
		PullRequest mockPR = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		PullRequestContainerEntity mockPrEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class)))
				.thenReturn(mockPrEntity);
		PullRequestScanEntity mockScanEntity = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(mockScanEntity.getId()).thenReturn(scanEntityId);
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any(PullRequestScanEntity.class)))
				.thenReturn(mockScanEntity);
		return mockPR;
	}

	private long saveScan(PullRequest pr, PullRequestViolationEntity... violations) {
		PRScanTimings timings = new PRScanTimings(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 1,
				"CHANGED_FILES", "INDIVIDUAL_FILES", List.of(), true);
		return scanResultService.savePullRequestScan(pr, 0,
				new ArrayList<>(Arrays.asList(violations)), new ArrayList<>(), 0L, timings);
	}

	@Test
	public void executionSnapshotIsSavedWithThePrimaryScanRow() {
		PullRequest pr = stubSavePersistence(42L);
		var snapshot = new com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot(
				1, 99L, "Original", RulePriority.MEDIUM, List.of(), List.of(), null);
		var summary = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary(0,
				List.of(new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution(
						"Regex", "FAILED", 10, null)), snapshot);
		PRScanTimings timings = new PRScanTimings(0, 0, 0, 0, 0, 0, 0, 0, 0, "FULL", "FULL", List.of(), true);
		scanResultService.savePullRequestScan(pr, 0, new ArrayList<>(), new ArrayList<>(), 0, timings, summary);
		var saved = org.mockito.ArgumentCaptor.forClass(PullRequestScanEntity.class);
		BDDMockito.verify(mockScanRepo).saveAndFlush(saved.capture());
		Assertions.assertEquals(snapshot, com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec
				.decode(saved.getValue().getExecutionSnapshotJson()));
		Assertions.assertEquals(0, saved.getValue().getRulesEvaluated());
	}

	@Test
	public void explicitScannerFailureOverridesTimingAndIsNeverListedAsSkipped() {
		PullRequestScanEntity scan = makeMockScanEntity(1L, 1L, 100L, 1000L, ScanStatus.DONE, "");
		makeMockContainerEntity("123", "repo", "author", 1000L, ApiType.BITBUCKET_CLOUD.getTypeName(), scan);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(scan));
		BDDMockito.when(scan.getRulesEvaluated()).thenReturn(1);
		BDDMockito.when(scan.getScannerTimingsJson()).thenReturn("[{\"scannerName\":\"Regex\",\"durationMs\":10}]");
		BDDMockito.when(scan.getScannerExecutionsJson())
				.thenReturn("[{\"scannerName\":\"Regex\",\"status\":\"FAILED\",\"durationMs\":10}]");
		var result = scanResultService.getScanResultForScanId("1");
		Assertions.assertEquals(1, result.getExecutionSummary().scanners().size());
		Assertions.assertEquals(0, result.getExecutionSummary().getRanCount());
		Assertions.assertEquals(0, result.getExecutionSummary().getSkippedCount());
		Assertions.assertEquals(1, result.getExecutionSummary().getFailedCount());
	}

	@Test
	public void testCountScansToday() {
		BDDMockito.when(mockScanRepo.countByEndDateBetween(BDDMockito.anyLong(),
				BDDMockito.anyLong())).thenReturn(3L);

		Assertions.assertEquals(3L, scanResultService.countScansToday());

		// Bounds must span from local midnight through "now" - not, say, UTC midnight -
		// since the metric is "scans today" per the server's own clock.
		org.mockito.ArgumentCaptor<Long> startCaptor =
				org.mockito.ArgumentCaptor.forClass(Long.class);
		org.mockito.ArgumentCaptor<Long> endCaptor =
				org.mockito.ArgumentCaptor.forClass(Long.class);
		BDDMockito.verify(mockScanRepo).countByEndDateBetween(startCaptor.capture(),
				endCaptor.capture());
		long expectedStartOfDay = LocalDateTime.now().toLocalDate()
				.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
		Assertions.assertEquals(expectedStartOfDay, startCaptor.getValue());
		MatcherAssert.assertThat(endCaptor.getValue(),
				Matchers.greaterThanOrEqualTo(startCaptor.getValue()));
	}

	@Test
	public void testSaveNew() {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		RulePriority severity = RulePriority.HIGH;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severity, isNewViolation);

		List<PullRequestViolationEntity> violations = new ArrayList<>();
		violations.add(ve);

		PullRequest mockPR = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		BDDMockito.when(mockPR.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(mockPR.getCommitHash()).thenReturn("abc123");

		long prEntityId = 42L;
		long scanEntityId = 1337L;

		PullRequestContainerEntity mockPrEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockPrEntity.getId()).thenReturn(prEntityId);

		PullRequestScanEntity mockScanEntity = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(mockScanEntity.getId()).thenReturn(scanEntityId);

		BDDMockito.when(mockPrRepo.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(null);

		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class)))
				.thenReturn(mockPrEntity);

		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any(PullRequestScanEntity.class)))
				.thenReturn(mockScanEntity);
		PRScanTimings timings = new PRScanTimings(100L, 5000L, 1000L, 2500L, 500L,
				750L, 200L, 50L, 3, "CHANGED_FILES", "INDIVIDUAL_FILES",
				List.of(new PRScanTimings.ScannerTiming("RegexScanner", 2500L)), true);
		scanResultService.savePullRequestScan(mockPR, 0, violations, new ArrayList<>(), 12345L,
				timings);

		BDDMockito.verify(mockPrRepo, BDDMockito.times(2))
				.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class));
		BDDMockito.verify(mockVioRepo).save(BDDMockito.any());

		org.mockito.ArgumentCaptor<PullRequestScanEntity> savedScanCaptor =
				org.mockito.ArgumentCaptor.forClass(PullRequestScanEntity.class);
		BDDMockito.verify(mockScanRepo).saveAndFlush(savedScanCaptor.capture());
		Assertions.assertEquals(12345L, savedScanCaptor.getValue().getSourceSizeBytes());
		// The scanned commit, so live verification re-reads the file exactly as scanned.
		Assertions.assertEquals("abc123", savedScanCaptor.getValue().getCommitHash());
		Assertions.assertEquals(5000L, savedScanCaptor.getValue().getTotalDurationMs());
		Assertions.assertEquals(1000L,
				savedScanCaptor.getValue().getSourcePreparationDurationMs());
		Assertions.assertEquals(2500L,
				savedScanCaptor.getValue().getScannerExecutionDurationMs());
		Assertions.assertEquals(500L,
				savedScanCaptor.getValue().getResultProcessingDurationMs());
		Assertions.assertEquals(750L,
				savedScanCaptor.getValue().getScmReportingDurationMs());
		Assertions.assertEquals(100L, savedScanCaptor.getValue().getQueueWaitDurationMs());
		Assertions.assertEquals(200L, savedScanCaptor.getValue().getPersistenceDurationMs());
		Assertions.assertEquals(50L, savedScanCaptor.getValue().getCleanupDurationMs());
		Assertions.assertEquals(3, savedScanCaptor.getValue().getChangedFileCount());
		Assertions.assertEquals("CHANGED_FILES", savedScanCaptor.getValue().getScanScope());
		Assertions.assertEquals("INDIVIDUAL_FILES",
				savedScanCaptor.getValue().getSourceStrategy());
		Assertions.assertTrue(savedScanCaptor.getValue().isPerformanceComplete());
		MatcherAssert.assertThat(savedScanCaptor.getValue().getScannerTimingsJson(),
				Matchers.containsString("RegexScanner"));
	}

	private PullRequestScanEntity savedScan() {
		org.mockito.ArgumentCaptor<PullRequestScanEntity> captor =
				org.mockito.ArgumentCaptor.forClass(PullRequestScanEntity.class);
		BDDMockito.verify(mockScanRepo).saveAndFlush(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testSaveMarksScanBlockedByNewBlockingFinding() {
		PullRequest pr = stubSavePersistence(1L);

		saveScan(pr, makeMockVioEntity("rule", true, "a.java", 1, RulePriority.HIGH, true));

		Assertions.assertTrue(savedScan().isBlocked());
	}

	@Test
	public void testSaveDoesNotMarkBlockedForPreexistingBlockingFinding() {
		PullRequest pr = stubSavePersistence(1L);

		saveScan(pr, makeMockVioEntity("rule", true, "a.java", 1, RulePriority.HIGH, false));

		Assertions.assertFalse(savedScan().isBlocked());
	}

	@Test
	public void testSaveDoesNotMarkBlockedForNewNonBlockingFinding() {
		PullRequest pr = stubSavePersistence(1L);

		saveScan(pr, makeMockVioEntity("rule", false, "a.java", 1, RulePriority.LOW, true));

		Assertions.assertFalse(savedScan().isBlocked());
	}

	@Test
	public void testFinalizePerformance() {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		BDDMockito.when(mockScanRepo.findById(Long.valueOf(42L)))
				.thenReturn(Optional.of(scan));

		scanResultService.finalizePerformance(42L, 5000L, 200L, 50L, 6000L);

		Assertions.assertEquals(5000L, scan.getTotalDurationMs());
		Assertions.assertEquals(200L, scan.getPersistenceDurationMs());
		Assertions.assertEquals(50L, scan.getCleanupDurationMs());
		Assertions.assertEquals(Instant.ofEpochMilli(6000L),
				scan.getEndDate().atZone(ZoneId.systemDefault()).toInstant());
		Assertions.assertTrue(scan.isPerformanceComplete());
		BDDMockito.verify(mockScanRepo).saveAndFlush(scan);
	}

	@Test
	public void testGetLastScans() {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		BDDMockito.when(mockScanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(scan)));
		MatcherAssert.assertThat(scanResultService.getLastScans(1), Matchers.contains(scan));
	}

	@Test
	public void testCountPrs() {
		BDDMockito.when(mockPrRepo.count()).thenReturn(2L);
		Assertions.assertEquals(2L, scanResultService.countPrs());

		BDDMockito.when(mockPrRepo.count()).thenReturn(0L);
		Assertions.assertEquals(0L, scanResultService.countPrs());
	}

	@Test
	public void testCountRepos() {
		BDDMockito.when(mockRepoRepo.count()).thenReturn(3L);
		Assertions.assertEquals(3L, scanResultService.countRepos());

		BDDMockito.when(mockRepoRepo.count()).thenReturn(0L);
		Assertions.assertEquals(0L, scanResultService.countRepos());
	}

	@Test
	public void testMarkPrResolvedNotExist() {
		PullRequest pr = PullRequestTest.buildStandardPR();

		BDDMockito.when(mockPrRepo.findByApiLabelAndRepoNameAndPrId(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(List.of());
		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));

		scanResultService.markPrResolved(pr);

		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Creating and marking resolved anyway"));
		BDDMockito.verify(mockPrRepo).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testMarkPrResolved() {
		PullRequest pr = PullRequestTest.buildStandardPR();
		PullRequestContainerEntity pre = new PullRequestContainerEntity(pr);

		BDDMockito.when(mockPrRepo.findByApiLabelAndRepoNameAndPrId(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(List.of(pre));
		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		scanResultService.markPrResolved(pr);

		BDDMockito.verify(mockPrRepo).saveAndFlush(pre);
	}

	@Test
	public void testMarkPrResolvedRecordsHowAndWhenItClosedOnce() {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.MERGED);
		pr.setUpdateTime(5_000L);
		pr.setCommitHash("abc");
		PullRequestContainerEntity pre = new PullRequestContainerEntity(pr);
		BDDMockito.when(mockPrRepo.findByApiLabelAndRepoNameAndPrId(pr.getApiLabel(),
				pr.getRepoName(), pr.getPrId())).thenReturn(List.of(pre));

		scanResultService.markPrResolved(pr, true);
		// The sync reports the same merge later; it must not move the time or lose "pending"
		pr.setUpdateTime(9_000L);
		scanResultService.markPrResolved(pr);

		Assertions.assertEquals(PullRequestState.MERGED, pre.getClosedState());
		Assertions.assertEquals(5_000L, pre.getClosedAt());
		Assertions.assertEquals("abc", pre.getMergedCommit());
		Assertions.assertTrue(pre.isScanPendingAtClose());
	}

	@Test
	public void testMarkPrResolvedWithoutAStateRecordsNoClose() {
		// Closed as unsyncable: the integration is gone and nobody knows how it ended
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(null);
		PullRequestContainerEntity pre = new PullRequestContainerEntity(pr);
		BDDMockito.when(mockPrRepo.findByApiLabelAndRepoNameAndPrId(pr.getApiLabel(),
				pr.getRepoName(), pr.getPrId())).thenReturn(List.of(pre));

		scanResultService.markPrResolved(pr);

		Assertions.assertTrue(pre.isResolved());
		Assertions.assertNull(pre.getClosedState());
		Assertions.assertNull(pre.getClosedAt());
	}

	@Test
	public void testMarkPrResolvedResolvesEveryDuplicateRow() {
		// Older data holds two rows for one Pull Request; a single-row lookup threw on them
		// and left the Pull Request open.
		PullRequest pr = PullRequestTest.buildStandardPR();
		PullRequestContainerEntity first = new PullRequestContainerEntity(pr);
		PullRequestContainerEntity second = new PullRequestContainerEntity(pr);
		BDDMockito.when(mockPrRepo.findByApiLabelAndRepoNameAndPrId(pr.getApiLabel(),
				pr.getRepoName(), pr.getPrId())).thenReturn(List.of(first, second));

		scanResultService.markPrResolved(pr);

		Assertions.assertTrue(first.isResolved());
		Assertions.assertTrue(second.isResolved());
		BDDMockito.verify(mockPrRepo).saveAndFlush(first);
		BDDMockito.verify(mockPrRepo).saveAndFlush(second);
	}

	@Test
	public void testGetScanResultForScanId() throws Exception {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		RulePriority severity = RulePriority.HIGH;
		int severityValue = 1;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severity, isNewViolation);

		long id = 1L;
		String prId = "123";
		String author = "author";
		long submitDate = 1L;
		long startDate = 100L;
		long endDate = 1000L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		String repoName = "repo";

		PullRequestScanEntity se =
				makeMockScanEntity(id, submitDate, startDate, endDate, ScanStatus.DONE, "", ve);

		makeMockContainerEntity(prId, repoName, author, endDate, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		Assertions.assertEquals(id, result.getId());
		Assertions.assertEquals(prId, result.getPrId());
		Assertions.assertEquals(author, result.getAuthor());
		Assertions.assertEquals(apiType, result.getApiLabel());
		Assertions.assertEquals(repoName, result.getRepoName());
		Assertions.assertEquals(repoName + " #" + prId, result.getDisplayName(),
				"a pull request reads \"repo #number\" in the report, as in every list");
		Assertions.assertEquals(1, result.getViolations().size());
		PRScanResultViolation violation = result.getViolations().get(0);
		Assertions.assertEquals(vioName, violation.getViolationName());
		Assertions.assertEquals(lineNum, violation.getLineNumber());
		Assertions.assertEquals(severity.getName(), violation.getSeverity());
		Assertions.assertEquals(severityValue, violation.getSeverityValue());
		Assertions.assertEquals(fileName, violation.getFileName());
		Assertions.assertEquals("No guidance written for this rule yet.", violation.getMessage());
	}

	@Test
	public void testGetScanResultIncludesRuleDocumentationUrl() throws Exception {
		String ruleName = "Documented rule";
		PullRequestViolationEntity violation = makeMockVioEntity(ruleName, false, "App.java", 8,
				RulePriority.HIGH, true);
		PullRequestScanEntity scan = makeMockScanEntity(1L, 1L, 100L, 1000L, ScanStatus.DONE,
				"", violation);
		makeMockContainerEntity("123", "repo", "author", 1000L,
				ApiType.BITBUCKET_CLOUD.getTypeName(), scan);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(scan));

		RuleEntity rule = BDDMockito.mock(RuleEntity.class);
		BDDMockito.when(rule.getName()).thenReturn(ruleName);
		BDDMockito.when(rule.getMessage()).thenReturn("Follow the safe pattern.");
		BDDMockito.when(rule.getExternalUrl()).thenReturn("https://example.invalid/rules/safe");
		BDDMockito.when(mockRuleService.getRulesByNames(Set.of(ruleName)))
				.thenReturn(List.of(rule));

		PRScanResult result = scanResultService.getScanResultForScanId("1");

		Assertions.assertEquals("https://example.invalid/rules/safe",
				result.getViolations().get(0).getExternalUrl());
	}

	@Test
	public void testGetScanResultForScanIdFetchesCodeSnippet() throws Exception {
		String vioName = "violation";
		String fileName = "foo/bar.java";
		int lineNum = 5;
		PullRequestViolationEntity ve = makeMockVioEntity(vioName, false, fileName, lineNum,
				RulePriority.HIGH, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se =
				makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));

		StringBuilder fileContent = new StringBuilder();
		for (int i = 1; i <= 10; i++) {
			fileContent.append("line").append(i).append("\n");
		}

		stubScmFileContent(apiType, fileName, fileContent.toString());

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		Assertions.assertEquals(1, result.getCodeFiles().size());
		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertEquals(fileName, codeFile.getFileName());
		Assertions.assertEquals(1, codeFile.getFindingCount());
		Assertions.assertTrue(codeFile.isSourceAvailable());
		Assertions.assertEquals(1, codeFile.getBlocks().size());

		List<PRScanResultCodeLine> snippet = codeFile.getBlocks().get(0).getLines();
		Assertions.assertFalse(snippet.isEmpty());
		long violationLineCount =
				snippet.stream().filter(PRScanResultCodeLine::isViolationLine).count();
		Assertions.assertEquals(1, violationLineCount);
		PRScanResultCodeLine violationLine = snippet.stream()
				.filter(PRScanResultCodeLine::isViolationLine).findFirst().orElseThrow();
		Assertions.assertEquals(lineNum, violationLine.getLineNumber());
		Assertions.assertEquals("line5", violationLine.getText());
	}

	@Test
	public void testGetScanResultForScanIdRendersFileOnceWithEveryFlaggedLineHighlighted()
			throws Exception {
		// Two violations in the same file, close enough that their +/-5 context windows overlap:
		// the report must show the file once, as a single continuous block, with both lines
		// highlighted - not two near-identical snippets the way the old per-violation layout did.
		String fileName = "foo/bar.java";
		PullRequestViolationEntity first =
				makeMockVioEntity("violationA", false, fileName, 5, RulePriority.HIGH, true);
		PullRequestViolationEntity second =
				makeMockVioEntity("violationB", false, fileName, 8, RulePriority.HIGH, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se =
				makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", first, second);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));

		StringBuilder fileContent = new StringBuilder();
		for (int i = 1; i <= 20; i++) {
			fileContent.append("line").append(i).append("\n");
		}
		stubScmFileContent(apiType, fileName, fileContent.toString());

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		Assertions.assertEquals(1, result.getCodeFiles().size());
		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertEquals(2, codeFile.getFindingCount());
		Assertions.assertEquals(1, codeFile.getBlocks().size());

		List<PRScanResultCodeLine> snippet = codeFile.getBlocks().get(0).getLines();
		// Merged window is [5-5, 8+5] = lines 1 through 13.
		Assertions.assertEquals(1, snippet.get(0).getLineNumber());
		Assertions.assertEquals(13, snippet.get(snippet.size() - 1).getLineNumber());
		List<Integer> highlighted = snippet.stream().filter(PRScanResultCodeLine::isViolationLine)
				.map(PRScanResultCodeLine::getLineNumber).collect(Collectors.toList());
		MatcherAssert.assertThat(highlighted, Matchers.contains(5, 8));
	}

	@Test
	public void testGetScanResultForScanIdListsFileEvenWhenSourceUnavailable() throws Exception {
		// getFileContent returns null when the file was deleted since the scan ran, renamed, or
		// the SCM call failed. The file must still be listed with its finding count so the report
		// can say "source unavailable" rather than rendering an unexplained blank.
		String fileName = "foo/bar.java";
		PullRequestViolationEntity ve =
				makeMockVioEntity("violation", false, fileName, 5, RulePriority.HIGH, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		stubScmFileContent(apiType, fileName, null);

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		Assertions.assertEquals(1, result.getCodeFiles().size());
		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertEquals(fileName, codeFile.getFileName());
		Assertions.assertEquals(1, codeFile.getFindingCount());
		Assertions.assertFalse(codeFile.isSourceAvailable());
		Assertions.assertTrue(codeFile.getBlocks().isEmpty());
	}

	@Test
	public void testSourceIsReadAtTheScannedCommitWhenTheBranchIsGone() throws Exception {
		// A merged or deleted branch 404s by name; the scanned commit is still readable, so the
		// report keeps showing the code its findings point at.
		String fileName = "foo/bar.java";
		PullRequestViolationEntity ve =
				makeMockVioEntity("violation", false, fileName, 2, RulePriority.HIGH, true);
		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		BDDMockito.when(se.getCommitHash()).thenReturn("59681a5");
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		AbstractScmIntegrationEntity mockIntegration =
				BDDMockito.mock(AbstractScmIntegrationEntity.class);
		IScmApi mockScmApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockIntegration.createApi()).thenReturn(mockScmApi);
		BDDMockito.when(mockApiService.findByLabel(apiType)).thenReturn(mockIntegration);
		BDDMockito.when(mockScmApi.getFileContent(BDDMockito.any(), BDDMockito.eq(fileName)))
				.thenReturn(null);
		BDDMockito.when(mockScmApi.fetchFileAtCommit("repo", "59681a5", fileName)).thenReturn(
				com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch
						.found("line one\nline two\nline three\n"));

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertTrue(codeFile.isSourceAvailable());
		Assertions.assertFalse(codeFile.getBlocks().isEmpty());
	}

	@Test
	public void testMissingSourceSaysWhyFromTheCommitRead() throws Exception {
		String fileName = "foo/bar.java";
		PullRequestViolationEntity ve =
				makeMockVioEntity("violation", false, fileName, 2, RulePriority.HIGH, true);
		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		BDDMockito.when(se.getCommitHash()).thenReturn("59681a5");
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		AbstractScmIntegrationEntity mockIntegration =
				BDDMockito.mock(AbstractScmIntegrationEntity.class);
		IScmApi mockScmApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockIntegration.createApi()).thenReturn(mockScmApi);
		BDDMockito.when(mockApiService.findByLabel(apiType)).thenReturn(mockIntegration);
		BDDMockito.when(mockScmApi.fetchFileAtCommit("repo", "59681a5", fileName)).thenReturn(
				com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch
						.unavailable("The file is larger than 2 MB, so it is not shown."));

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertFalse(codeFile.isSourceAvailable());
		Assertions.assertEquals("The file is larger than 2 MB, so it is not shown.",
				codeFile.getSourceUnavailableReason());
	}

	@Test
	public void testMissingSourceSaysWhenTheIntegrationIsGone() throws Exception {
		String fileName = "foo/bar.java";
		PullRequestViolationEntity ve =
				makeMockVioEntity("violation", false, fileName, 2, RulePriority.HIGH, true);
		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		BDDMockito.when(mockApiService.findByLabel(apiType)).thenReturn(null);

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		Assertions.assertEquals(1, result.getCodeFiles().size());
		MatcherAssert.assertThat(result.getCodeFiles().get(0).getSourceUnavailableReason(),
				Matchers.containsString("no longer configured"));
	}

	@Test
	public void testFilesAreReadInParallelInOrderAndAFailedReadSaysSo() {
		java.util.concurrent.atomic.AtomicInteger inFlight = new java.util.concurrent.atomic.AtomicInteger();
		java.util.concurrent.atomic.AtomicInteger peak = new java.util.concurrent.atomic.AtomicInteger();
		List<String> names = List.of("a.java", "b.java", "c.java", "d.java", "boom.java");

		var results = PRScanResultService.fetchAll(names, name -> {
			peak.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
			try {
				Thread.sleep(80);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			inFlight.decrementAndGet();
			if (name.equals("boom.java")) {
				throw new IllegalStateException("network");
			}
			return com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch.found(name);
		});

		Assertions.assertEquals(names, new java.util.ArrayList<>(results.keySet()));
		Assertions.assertEquals("a.java", results.get("a.java").content());
		Assertions.assertFalse(results.get("boom.java").isFound());
		Assertions.assertTrue(peak.get() > 1, "reads overlap");
	}

	@Test
	public void testSensitiveFindingIsMaskedAndShownWithoutContext() throws Exception {
		// A secrets finding's line is the secret itself, and its neighbours are often the rest
		// of it (a PEM body), so the report shows where it is but never what it is.
		String fileName = "config/app.properties";
		PullRequestViolationEntity ve =
				makeMockVioEntity("Secret rule", false, fileName, 5, RulePriority.HIGH, true);
		stubRule("Secret rule", SENSITIVE_MODULE);
		String apiType = stubSingleScan(ve);
		stubScmFileContent(apiType, fileName, tenLinesWithSecretOn(5));

		PRScanResult result = this.scanResultService.getScanResultForScanId("1");

		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertEquals(1, codeFile.getBlocks().size());
		List<PRScanResultCodeLine> lines = codeFile.getBlocks().get(0).getLines();
		Assertions.assertEquals(1, lines.size());
		Assertions.assertEquals(5, lines.get(0).getLineNumber());
		Assertions.assertTrue(lines.get(0).isViolationLine());
		Assertions.assertEquals(PRScanResultService.MASKED_LINE_TEXT, lines.get(0).getText());
		assertSecretNotRendered(result);
	}

	/** Review finding "View source": a secret flagged by another finding in the file stays masked. */
	@Test
	public void testReviewSourceMasksSecretsFromOtherFindingsInTheFile() throws Exception {
		String fileName = "config/app.properties";
		PullRequestViolationEntity secret =
				makeMockVioEntity("Secret rule", false, fileName, 5, RulePriority.HIGH, true);
		PullRequestViolationEntity plain =
				makeMockVioEntity("Plain rule", false, fileName, 6, RulePriority.LOW, true);
		BDDMockito.when(plain.getId()).thenReturn(7L);
		stubRules(Map.of("Secret rule", SENSITIVE_MODULE, "Plain rule", "Plain"));
		String apiType = stubSingleScan(secret, plain);
		PullRequestScanEntity scan = mockScanRepo.findById(Long.valueOf(1L)).orElseThrow();
		BDDMockito.when(mockScanRepo.findById(1L)).thenReturn(scan);
		stubScmFileContent(apiType, fileName, tenLinesWithSecretOn(5));

		var source = this.scanResultService.reviewSource(1L, 7L).orElseThrow();

		Map<Integer, String> textByLine = source.file().getBlocks().stream()
				.flatMap(block -> block.getLines().stream())
				.collect(Collectors.toMap(PRScanResultCodeLine::getLineNumber, PRScanResultCodeLine::getText, (a, b) -> a));
		Assertions.assertEquals(PRScanResultService.MASKED_LINE_TEXT, textByLine.get(5));
		Assertions.assertEquals("line6", textByLine.get(6));
		textByLine.values().forEach(text -> MatcherAssert.assertThat(text, Matchers.not(Matchers.containsString(FAKE_SECRET))));
		Assertions.assertTrue(this.scanResultService.reviewSource(1L, 99L).isEmpty(), "an unknown finding has no source");
	}

	@Test
	public void testSensitiveLineInsideAnotherFindingsContextIsStillMasked() throws Exception {
		String fileName = "config/app.properties";
		PullRequestViolationEntity secret =
				makeMockVioEntity("Secret rule", false, fileName, 5, RulePriority.HIGH, true);
		PullRequestViolationEntity plain =
				makeMockVioEntity("Plain rule", false, fileName, 8, RulePriority.LOW, true);
		stubRules(Map.of("Secret rule", SENSITIVE_MODULE, "Plain rule", "Plain"));
		String apiType = stubSingleScan(secret, plain);
		stubScmFileContent(apiType, fileName, tenLinesWithSecretOn(5));

		PRScanResult result = this.scanResultService.getScanResultForScanId("1");

		List<PRScanResultCodeLine> lines =
				result.getCodeFiles().get(0).getBlocks().get(0).getLines();
		// The plain finding's +/-5 window, clipped to the file: lines 3 through 10.
		Assertions.assertEquals(3, lines.get(0).getLineNumber());
		Assertions.assertEquals(10, lines.get(lines.size() - 1).getLineNumber());
		Map<Integer, String> textByLine = lines.stream().collect(Collectors
				.toMap(PRScanResultCodeLine::getLineNumber, PRScanResultCodeLine::getText));
		Assertions.assertEquals(PRScanResultService.MASKED_LINE_TEXT, textByLine.get(5));
		Assertions.assertEquals("line8", textByLine.get(8));
		assertSecretNotRendered(result);
	}

	@Test
	public void testSensitiveContextWindowDoesNotSwallowAnEarlierPlainWindow() throws Exception {
		// Windows are merged by start line, not by finding line: a plain finding after a
		// secrets finding opens its window earlier than the secret's own single line.
		String fileName = "config/app.properties";
		PullRequestViolationEntity secret =
				makeMockVioEntity("Secret rule", false, fileName, 6, RulePriority.HIGH, true);
		PullRequestViolationEntity plain =
				makeMockVioEntity("Plain rule", false, fileName, 7, RulePriority.LOW, true);
		stubRules(Map.of("Secret rule", SENSITIVE_MODULE, "Plain rule", "Plain"));
		String apiType = stubSingleScan(secret, plain);
		stubScmFileContent(apiType, fileName, tenLinesWithSecretOn(6));

		PRScanResult result = this.scanResultService.getScanResultForScanId("1");

		PRScanResultFile codeFile = result.getCodeFiles().get(0);
		Assertions.assertEquals(1, codeFile.getBlocks().size());
		List<PRScanResultCodeLine> lines = codeFile.getBlocks().get(0).getLines();
		Assertions.assertEquals(2, lines.get(0).getLineNumber());
		Assertions.assertEquals(10, lines.get(lines.size() - 1).getLineNumber());
		assertSecretNotRendered(result);
	}

	@Test
	public void testFindingFromANonSensitiveModuleIsNotMasked() throws Exception {
		String fileName = "config/app.properties";
		PullRequestViolationEntity ve =
				makeMockVioEntity("Plain rule", false, fileName, 5, RulePriority.LOW, true);
		stubRule("Plain rule", "Plain");
		String apiType = stubSingleScan(ve);
		stubScmFileContent(apiType, fileName, tenLinesWithSecretOn(5));

		PRScanResult result = this.scanResultService.getScanResultForScanId("1");

		List<PRScanResultCodeLine> lines =
				result.getCodeFiles().get(0).getBlocks().get(0).getLines();
		Assertions.assertEquals(10, lines.size());
		Assertions.assertEquals("key=" + FAKE_SECRET, lines.get(4).getText());
	}

	private String stubSingleScan(PullRequestViolationEntity... violations) {
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se =
				makeMockScanEntity(1L, 1L, 100L, 1000L, ScanStatus.DONE, "", violations);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));
		return apiType;
	}

	private void stubRule(String ruleName, String module) {
		stubRules(Map.of(ruleName, module));
	}

	private void stubRules(Map<String, String> moduleByRuleName) {
		List<RuleEntity> rules = moduleByRuleName.entrySet().stream().map(entry -> {
			RuleDto dto = BDDMockito.mock(RuleDto.class);
			BDDMockito.when(dto.getModule()).thenReturn(entry.getValue());
			RuleEntity rule = BDDMockito.mock(RuleEntity.class);
			BDDMockito.when(rule.getName()).thenReturn(entry.getKey());
			BDDMockito.when(rule.getMessage()).thenReturn("message");
			BDDMockito.when(rule.toDto()).thenReturn(dto);
			return rule;
		}).collect(Collectors.toList());
		BDDMockito.when(mockRuleService.getRulesByNames(moduleByRuleName.keySet()))
				.thenReturn(rules);
	}

	private static String tenLinesWithSecretOn(int secretLine) {
		// No trailing newline, so the file is exactly ten lines long.
		List<String> lines = new ArrayList<>();
		for (int i = 1; i <= 10; i++) {
			lines.add(i == secretLine ? "key=" + FAKE_SECRET : "line" + i);
		}
		return String.join("\n", lines);
	}

	private static void assertSecretNotRendered(PRScanResult result) {
		result.getCodeFiles().stream().flatMap(file -> file.getBlocks().stream())
				.flatMap(block -> block.getLines().stream())
				.forEach(line -> MatcherAssert.assertThat(line.getText(),
						Matchers.not(Matchers.containsString(FAKE_SECRET))));
	}

	private void stubScmFileContent(String apiType, String fileName, String fileContent) {
		AbstractScmIntegrationEntity mockIntegration =
				BDDMockito.mock(AbstractScmIntegrationEntity.class);
		IScmApi mockScmApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockIntegration.createApi()).thenReturn(mockScmApi);
		BDDMockito.when(mockApiService.findByLabel(apiType)).thenReturn(mockIntegration);
		BDDMockito.when(mockScmApi.getFileContent(BDDMockito.any(), BDDMockito.eq(fileName)))
				.thenReturn(fileContent);
	}

	@Test
	public void testGetScanWithFiltersNeverFetchesCodeSnippet() throws Exception {
		// Regression guard: list-view results (getScanResultsWithFilters) must never fetch
		// file content, even when an SCM integration is available - only the single-scan
		// report view (getScanResultForScanId) does, to avoid reintroducing per-row latency.
		String vioName = "violation";
		String fileName = "foo/bar.java";
		PullRequestViolationEntity ve =
				makeMockVioEntity(vioName, false, fileName, 1, RulePriority.HIGH, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se =
				makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "", ve);
		PullRequestContainerEntity ce =
				makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);

		AbstractScmIntegrationEntity mockIntegration =
				BDDMockito.mock(AbstractScmIntegrationEntity.class);
		IScmApi mockScmApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockIntegration.createApi()).thenReturn(mockScmApi);
		BDDMockito.when(mockApiService.findByLabel(apiType)).thenReturn(mockIntegration);

		BDDMockito.when(mockScanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));
		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(ce)));
		BDDMockito.when(mockVioRepo.findAllNonMCRGroupByScan(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));

		this.scanResultService.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0);
		this.scanResultService.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 0);
		this.scanResultService.getScanResultsWithFilters(PRResultFilter.VIOLATIONS, 10, 0);

		BDDMockito.verify(mockScmApi, BDDMockito.never()).getFileContent(BDDMockito.any(),
				BDDMockito.any());
	}

	@Test
	public void testGetScanWithFilters() throws Exception {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		RulePriority severity = RulePriority.HIGH;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severity, isNewViolation);

		long id = 1L;
		String prId = "123";
		String author = "author";
		long submitDate = 1L;
		long startDate = 100L;
		long endDate = 1000L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		String repoName = "repo";

		PullRequestScanEntity se =
				makeMockScanEntity(id, submitDate, startDate, endDate, ScanStatus.DONE, "", ve);

		PullRequestContainerEntity ce =
				makeMockContainerEntity(prId, repoName, author, endDate, apiType, se);

		BDDMockito.when(mockScanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));
		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(ce)));
		BDDMockito.when(mockVioRepo.findAllNonMCRGroupByScan(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));
		PagedResult<PRScanResult> allResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0);
		PagedResult<PRScanResult> unresResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 0);
		PagedResult<PRScanResult> vioResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.VIOLATIONS, 10, 0);

		Assertions.assertEquals(1, allResult.content().size());
		Assertions.assertEquals(1, unresResult.content().size());
		Assertions.assertEquals(1, vioResult.content().size());
		Assertions.assertFalse(allResult.hasNext());
		Assertions.assertFalse(unresResult.hasNext());
		Assertions.assertFalse(vioResult.hasNext());

		for (PRScanResult result : Arrays.asList(allResult.content().get(0),
				unresResult.content().get(0), vioResult.content().get(0))) {
			Assertions.assertEquals(id, result.getId());
			Assertions.assertEquals(prId, result.getPrId());
			Assertions.assertEquals(author, result.getAuthor());
			Assertions.assertEquals(apiType, result.getApiLabel());
			Assertions.assertEquals(repoName, result.getRepoName());
			Assertions.assertEquals(1, result.getViolations().size());
			PRScanResultViolation violation = result.getViolations().get(0);
			Assertions.assertEquals(vioName, violation.getViolationName());
			Assertions.assertEquals(lineNum, violation.getLineNumber());
			Assertions.assertEquals(severity.getName(), violation.getSeverity());
			Assertions.assertEquals(fileName, violation.getFileName());
			Assertions.assertEquals("No guidance written for this rule yet.", violation.getMessage());
		}

	}

	@Test
	public void testRuleGuidanceIsLookedUpOncePerDistinctRuleName() throws Exception {
		// This is what made /scan/results/all time out. generateResultForViolation used to
		// issue a database query per violation to fetch rule guidance, and the violation
		// list used to be mapped twice - once for violations, once for MCR findings. A scan
		// with 416 violations therefore cost 832 queries for one row of the page.
		//
		// It now batches every distinct rule name across the whole page into a single
		// getRulesByNames(...) call (see buildRuleCache) instead of querying one name at a
		// time - even an indexed per-name lookup still pays a full DB round trip, and that
		// was still enough to make the endpoint slow.
		//
		// Six violations across three distinct rule names must now cost one batched lookup.
		PullRequestViolationEntity[] violations = new PullRequestViolationEntity[] {
				makeMockVioEntity("RuleA", false, "a.java", 1, RulePriority.HIGH, false),
				makeMockVioEntity("RuleA", false, "a.java", 2, RulePriority.HIGH, false),
				makeMockVioEntity("RuleA", false, "a.java", 3, RulePriority.HIGH, false),
				makeMockVioEntity("RuleB", false, "b.java", 4, RulePriority.LOW, false),
				makeMockVioEntity("RuleB", false, "b.java", 5, RulePriority.LOW, false),
				makeMockVioEntity("MCR Match: something", false, "c.java", 6, RulePriority.HIGH,
						false)};

		PullRequestScanEntity se = makeMockScanEntity(1L, 1L, 100L, 1000L, ScanStatus.DONE, "",
				violations);
		makeMockContainerEntity("123", "repo", "author", 1000L,
				ApiType.BITBUCKET_CLOUD.getTypeName(), se);

		BDDMockito.when(mockScanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));

		PagedResult<PRScanResult> results =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0);

		Assertions.assertEquals(1, results.content().size());
		// Ordinary violations and MCR findings are still separated correctly.
		Assertions.assertEquals(5, results.content().get(0).getViolations().size());
		Assertions.assertEquals(1, results.content().get(0).getMcrFindings().size());

		// Three distinct names across six violations: RuleA, RuleB and the MCR rule, fetched
		// in a single batched call rather than three individual ones.
		Set<String> expectedNames =
				new HashSet<>(Arrays.asList("RuleA", "RuleB", "MCR Match: something"));
		BDDMockito.verify(mockRuleService, BDDMockito.times(1)).getRulesByNames(expectedNames);
		BDDMockito.verifyNoMoreInteractions(mockRuleService);
	}

	@Test
	public void testGetScanResultForScanIdSortsViolationsBySeverity() throws Exception {
		// Severity-first triage (Tier C backlog item): violations must come back ordered
		// High -> Low regardless of the order they were persisted in.
		PullRequestViolationEntity low =
				makeMockVioEntity("LowRule", false, "a.java", 1, RulePriority.LOW, true);
		PullRequestViolationEntity high =
				makeMockVioEntity("HighRule", false, "b.java", 2, RulePriority.HIGH, true);
		PullRequestViolationEntity medium =
				makeMockVioEntity("MediumRule", false, "c.java", 3, RulePriority.MEDIUM, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "",
				low, high, medium);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		List<Integer> severityOrder = result.getViolations().stream()
				.map(PRScanResultViolation::getSeverityValue).collect(Collectors.toList());
		Assertions.assertEquals(Arrays.asList(1, 3, 5), severityOrder);
	}

	@Test
	public void testGetScanResultForScanIdSortsMcrFindingsBySeverity() throws Exception {
		// mcrreport.html is fed by getMcrFindings(), not getViolations() - it needs the same
		// severity-first ordering.
		PullRequestViolationEntity low = makeMockVioEntity("MCR Match: LowFinding", false,
				"a.java", 1, RulePriority.LOW, true);
		PullRequestViolationEntity high = makeMockVioEntity("MCR Match: HighFinding", false,
				"b.java", 2, RulePriority.HIGH, true);
		PullRequestViolationEntity medium = makeMockVioEntity("MCR Match: MediumFinding", false,
				"c.java", 3, RulePriority.MEDIUM, true);

		long id = 1L;
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		PullRequestScanEntity se = makeMockScanEntity(id, 1L, 100L, 1000L, ScanStatus.DONE, "",
				low, high, medium);
		makeMockContainerEntity("123", "repo", "author", 1000L, apiType, se);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(se));

		PRScanResult result = this.scanResultService.getScanResultForScanId(String.valueOf(id));

		List<Integer> severityOrder = result.getMcrFindings().stream()
				.map(PRScanResultViolation::getSeverityValue).collect(Collectors.toList());
		Assertions.assertEquals(Arrays.asList(1, 3, 5), severityOrder);
	}

	@Test
	public void findingsOfARuleEditedAfterTheScanAreMarkedChangedAndTheCheckRunsOncePerRule() {
		RuleEntity edited = BDDMockito.mock(RuleEntity.class);
		BDDMockito.when(edited.getName()).thenReturn("Edited");
		BDDMockito.when(mockRuleService.getRulesByNames(BDDMockito.anyCollection()))
				.thenReturn(List.of(edited));
		BDDMockito.when(mockRuleService.changedAfter(edited, 5000L)).thenReturn(true);
		PullRequestViolationEntity first =
				makeMockVioEntity("Edited", true, "a.java", 1, RulePriority.HIGH, true);
		PullRequestViolationEntity second =
				makeMockVioEntity("Edited", true, "b.java", 2, RulePriority.HIGH, true);

		PRScanResult result = resultOf(first, second);

		Assertions.assertEquals(RuleChange.CHANGED, result.getViolations().get(0).getRuleChange());
		Assertions.assertEquals(RuleChange.CHANGED, result.getViolations().get(1).getRuleChange());
		BDDMockito.verify(mockRuleService, BDDMockito.times(1)).changedAfter(edited, 5000L);
	}

	@Test
	public void aFindingOfADeletedRuleIsMarkedDeleted() {
		BDDMockito.when(mockRuleService.getRule("Gone")).thenReturn(null);

		PRScanResult result = resultOf(
				makeMockVioEntity("Gone", true, "a.java", 1, RulePriority.HIGH, true));

		Assertions.assertEquals(RuleChange.DELETED, result.getViolations().get(0).getRuleChange());
	}

	@Test
	public void aFindingOfAnUntouchedRuleHasNoRuleChange() {
		RuleEntity same = BDDMockito.mock(RuleEntity.class);
		BDDMockito.when(same.getName()).thenReturn("Same");
		BDDMockito.when(mockRuleService.getRulesByNames(BDDMockito.anyCollection()))
				.thenReturn(List.of(same));
		BDDMockito.when(mockRuleService.changedAfter(same, 5000L)).thenReturn(false);

		PRScanResult result = resultOf(
				makeMockVioEntity("Same", true, "a.java", 1, RulePriority.HIGH, true));

		Assertions.assertNull(result.getViolations().get(0).getRuleChange());
	}

	@Test
	public void aMatchedCodeReviewFindingIsNeverMarkedAsADeletedRule() {
		// "MCR Match:" findings have no rule row by design, so they must not read as "Rule deleted".
		BDDMockito.when(mockRuleService.getRule("MCR Match: password")).thenReturn(null);

		PRScanResult result = resultOf(
				makeMockVioEntity("MCR Match: password", false, "a.java", 1, RulePriority.MEDIUM, true));

		Assertions.assertNull(result.getMcrFindings().get(0).getRuleChange());
	}

	private PRScanResult resultOf(PullRequestViolationEntity... violations) {
		PullRequestScanEntity scan =
				makeMockScanEntity(1L, 1L, 100L, 5000L, ScanStatus.DONE, "", violations);
		makeMockContainerEntity("123", "repo", "author", 5000L,
				ApiType.BITBUCKET_CLOUD.getTypeName(), scan);
		BDDMockito.when(mockScanRepo.findById(BDDMockito.any())).thenReturn(Optional.of(scan));
		return scanResultService.getScanResultForScanId("1");
	}

	private PullRequestContainerEntity makeMockContainerEntity(String prId, String repo,
			String author, long date, String apiLabel, PullRequestScanEntity... scans) {
		PullRequestContainerEntity ce = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(ce.getPrId()).thenReturn(prId);
		BDDMockito.when(ce.getRepoName()).thenReturn(repo);
		BDDMockito.when(ce.getAuthor()).thenReturn(author);
		BDDMockito.when(ce.getLastReviewedDate()).thenReturn(date);
		BDDMockito.when(ce.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(ce.getScans()).thenReturn(Arrays.asList(scans));
		for (PullRequestScanEntity scan : scans) {
			BDDMockito.when(scan.getContainer()).thenReturn(ce);
		}
		return ce;
	}

	private PullRequestScanEntity makeMockScanEntity(long id, long submitDate, long startDate,
			long endDate, ScanStatus status, String errorMessage,
			PullRequestViolationEntity... violations) {
		PullRequestScanEntity se = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(se.getId()).thenReturn(id);
		BDDMockito.when(se.getSubmitDateMillis()).thenReturn(submitDate);
		BDDMockito.when(se.getSubmitDate()).thenReturn(
				LocalDateTime.ofInstant(Instant.ofEpochMilli(submitDate), ZoneId.systemDefault()));
		BDDMockito.when(se.getStartDateMillis()).thenReturn(startDate);
		BDDMockito.when(se.getStartDate()).thenReturn(
				LocalDateTime.ofInstant(Instant.ofEpochMilli(startDate), ZoneId.systemDefault()));
		BDDMockito.when(se.getEndDateMillis()).thenReturn(endDate);
		BDDMockito.when(se.getEndDate()).thenReturn(
				LocalDateTime.ofInstant(Instant.ofEpochMilli(endDate), ZoneId.systemDefault()));
		BDDMockito.when(se.getNumViolations()).thenReturn((long) Arrays.asList(violations).size());
		BDDMockito.when(se.getViolations()).thenReturn(Arrays.asList(violations));
		BDDMockito.when(se.getStatus()).thenReturn(status);
		BDDMockito.when(se.getError()).thenReturn(errorMessage);
		for (PullRequestViolationEntity vio : violations) {
			BDDMockito.when(vio.getScan()).thenReturn(se);
		}
		return se;
	}

	private PullRequestViolationEntity makeMockVioEntity(String vioName, boolean blocking,
			String fileName,
			int lineNum, RulePriority severity, boolean isNewViolation) {
		PullRequestViolationEntity ve = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(ve.getViolationName()).thenReturn(vioName);
		BDDMockito.when(ve.getFileName()).thenReturn(fileName);
		BDDMockito.when(ve.getLineNum()).thenReturn(lineNum);
		BDDMockito.when(ve.getSeverity()).thenReturn(severity);
		BDDMockito.when(ve.isBlocking()).thenReturn(blocking);
		BDDMockito.when(ve.isNewViolation()).thenReturn(isNewViolation);
		return ve;
	}


	/** Saves a clean scan of {@code pr}, whose container row already exists as {@code container}. */
	private void saveCleanScanOf(PullRequest pr, PullRequestContainerEntity container) {
		BDDMockito.when(mockPrRepo.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(pr.getApiLabel(),
				pr.getRepoName(), pr.getPrId())).thenReturn(container);
		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class)))
				.thenAnswer(invocation -> invocation.getArgument(0));
		PullRequestScanEntity scanEntity = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(scanEntity.getId()).thenReturn(7L);
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any(PullRequestScanEntity.class)))
				.thenReturn(scanEntity);
		saveScan(pr);
	}

	@Test
	public void testACleanScanOfAnOpenPullRequestLeavesItOpen() {
		// "Resolved" used to be set by any scan with no new findings, so open pull requests showed as
		// Resolved, dropped out of the default results and were never synced to learn that they merged.
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.ACTIVE);
		PullRequestContainerEntity container = new PullRequestContainerEntity(pr);
		saveCleanScanOf(pr, container);
		Assertions.assertFalse(container.isResolved());
		Assertions.assertNull(container.getClosedState());
	}

	@Test
	public void testAScanOfAMergedPullRequestMarksItResolvedWithHowItClosed() {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.MERGED);
		pr.setUpdateTime(5_000L);
		PullRequestContainerEntity container = new PullRequestContainerEntity(pr);
		saveCleanScanOf(pr, container);
		Assertions.assertTrue(container.isResolved());
		Assertions.assertEquals(PullRequestState.MERGED, container.getClosedState());
	}

	@Test
	public void testAPullRequestReopenedAfterItClosedIsOpenAgain() {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.MERGED);
		pr.setUpdateTime(5_000L);
		PullRequestContainerEntity container = new PullRequestContainerEntity(pr);
		container.setResolved(true);
		container.recordClosed(PullRequestState.MERGED, 5_000L, "abc", false);
		pr.setState(PullRequestState.ACTIVE);
		pr.setUpdateTime(9_000L);
		saveCleanScanOf(pr, container);
		Assertions.assertFalse(container.isResolved());
		Assertions.assertNull(container.getClosedState());
	}

	@Test
	public void testAScanThatRacedAMergeDoesNotReopenIt() {
		// The scan fetched the pull request while it was open, then it merged before the scan finished.
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.ACTIVE);
		pr.setUpdateTime(5_000L);
		PullRequestContainerEntity container = new PullRequestContainerEntity(pr);
		container.setResolved(true);
		container.recordClosed(PullRequestState.MERGED, 9_000L, "abc", true);
		saveCleanScanOf(pr, container);
		Assertions.assertTrue(container.isResolved());
		Assertions.assertEquals(PullRequestState.MERGED, container.getClosedState());
	}

	@Test
	public void testAPullRequestWithoutAStateStaysOpenUntilTheSyncClosesIt() {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(null);
		PullRequestContainerEntity container = new PullRequestContainerEntity(pr);
		saveCleanScanOf(pr, container);
		Assertions.assertFalse(container.isResolved());
	}
}

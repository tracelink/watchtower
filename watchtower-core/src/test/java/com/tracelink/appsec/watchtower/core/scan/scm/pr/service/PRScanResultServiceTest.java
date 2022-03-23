package com.tracelink.appsec.watchtower.core.scan.scm.pr.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiType;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmRepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.result.PRScanResultViolation;

@ExtendWith(SpringExtension.class)
public class PRScanResultServiceTest {

	private PRScanResultService scanResultService;

	@MockBean
	private PRContainerRepository mockPrRepo;

	@MockBean
	private PRScanRepository mockScanRepo;

	@MockBean
	private PRViolationRepository mockVioRepo;

	@MockBean
	private ScmRepositoryRepository mockRepoRepo;

	@MockBean
	private RuleService mockRuleService;

	@MockBean
	private APIIntegrationService mockApiService;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(PRScanResultService.class);

	@BeforeEach
	public void setup() {
		this.scanResultService =
				new PRScanResultService(mockPrRepo, mockRepoRepo, mockScanRepo, mockVioRepo,
						mockRuleService, mockApiService);
	}

	@Test
	public void testSaveNew() {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		String severityName = "HIGH";
		int severityValue = 1;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severityName, severityValue, isNewViolation);

		List<PullRequestViolationEntity> violations = new ArrayList<>();
		violations.add(ve);

		PullRequest mockPR = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		BDDMockito.when(mockPR.getState()).thenReturn(PullRequestState.ACTIVE);

		long prEntityId = 42L;
		long scanEntityId = 1337L;

		PullRequestContainerEntity mockPrEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockPrEntity.getId()).thenReturn(prEntityId);

		PullRequestScanEntity mockScanEntity = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(mockScanEntity.getId()).thenReturn(scanEntityId);

		BDDMockito.when(mockPrRepo.findOneByApiLabelAndRepoNameAndPrId(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(null);

		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class)))
				.thenReturn(mockPrEntity);

		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any(PullRequestScanEntity.class)))
				.thenReturn(mockScanEntity);
		scanResultService.savePullRequestScan(mockPR, 0, violations, new ArrayList<>());

		BDDMockito.verify(mockPrRepo, BDDMockito.times(2))
				.saveAndFlush(BDDMockito.any(PullRequestContainerEntity.class));
		BDDMockito.verify(mockVioRepo).save(BDDMockito.any());
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

		BDDMockito.when(mockPrRepo.findOneByApiLabelAndRepoNameAndPrId(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(null);
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

		BDDMockito.when(mockPrRepo.findOneByApiLabelAndRepoNameAndPrId(BDDMockito.any(),
				BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(pre);
		BDDMockito.when(mockPrRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		scanResultService.markPrResolved(pr);

		BDDMockito.verify(mockPrRepo).saveAndFlush(pre);
	}

	@Test
	public void testGetScanResultForScanId() throws Exception {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		String severityName = "HIGH";
		int severityValue = 1;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severityName, severityValue, isNewViolation);

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
		Assertions.assertEquals(1, result.getViolations().size());
		PRScanResultViolation violation = result.getViolations().get(0);
		Assertions.assertEquals(vioName, violation.getViolationName());
		Assertions.assertEquals(lineNum, violation.getLineNumber());
		Assertions.assertEquals(severityName, violation.getSeverity());
		Assertions.assertEquals(severityValue, violation.getSeverityValue());
		Assertions.assertEquals(fileName, violation.getFileName());
		Assertions.assertEquals("Rule guidance not found", violation.getMessage());
	}

	@Test
	public void testGetScanWithFilters() throws Exception {
		String vioName = "violation";
		boolean blocking = false;
		String fileName = "foo/bar.java";
		int lineNum = 1;
		String severityName = "HIGH";
		int severityValue = 1;
		boolean isNewViolation = true;

		PullRequestViolationEntity ve = makeMockVioEntity(vioName, blocking, fileName, lineNum,
				severityName, severityValue, isNewViolation);

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
		BDDMockito.when(mockVioRepo.findAllGroupByScan(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(se)));
		List<PRScanResult> allResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0);
		List<PRScanResult> unresResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 0);
		List<PRScanResult> vioResult =
				this.scanResultService.getScanResultsWithFilters(PRResultFilter.VIOLATIONS, 10, 0);

		Assertions.assertEquals(1, allResult.size());
		Assertions.assertEquals(1, unresResult.size());
		Assertions.assertEquals(1, vioResult.size());

		for (PRScanResult result : Arrays.asList(allResult.get(0), unresResult.get(0),
				vioResult.get(0))) {
			Assertions.assertEquals(id, result.getId());
			Assertions.assertEquals(prId, result.getPrId());
			Assertions.assertEquals(author, result.getAuthor());
			Assertions.assertEquals(apiType, result.getApiLabel());
			Assertions.assertEquals(repoName, result.getRepoName());
			Assertions.assertEquals(1, result.getViolations().size());
			PRScanResultViolation violation = result.getViolations().get(0);
			Assertions.assertEquals(vioName, violation.getViolationName());
			Assertions.assertEquals(lineNum, violation.getLineNumber());
			Assertions.assertEquals(severityName, violation.getSeverity());
			Assertions.assertEquals(severityValue, violation.getSeverityValue());
			Assertions.assertEquals(fileName, violation.getFileName());
			Assertions.assertEquals("Rule guidance not found", violation.getMessage());
		}

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
			int lineNum, String severityName, int severityValue, boolean isNewViolation) {
		PullRequestViolationEntity ve = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(ve.getViolationName()).thenReturn(vioName);
		BDDMockito.when(ve.getFileName()).thenReturn(fileName);
		BDDMockito.when(ve.getLineNum()).thenReturn(lineNum);
		BDDMockito.when(ve.getSeverity()).thenReturn(severityName);
		BDDMockito.when(ve.getSeverityValue()).thenReturn(severityValue);
		BDDMockito.when(ve.isBlocking()).thenReturn(blocking);
		BDDMockito.when(ve.isNewViolation()).thenReturn(isNewViolation);
		return ve;
	}

}

package com.tracelink.appsec.watchtower.core.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanSettingsService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;

@ExtendWith(MockitoExtension.class)
class HomeDashboardServiceTest {
	@Mock MetricsCacheService metrics;
	@Mock PRScanRepository pullRequests;
	@Mock UploadScanRepository uploads;
	@Mock ImageScanRepository images;
	@Mock PRScanningService prScanning;
	@Mock UploadScanningService uploadScanning;
	@Mock ImageScanningService imageScanning;
	@Mock ScanRegistrationService scanRegistrationService;
	@Mock ApiIntegrationService apiIntegrationService;
	@Mock RepoScanViewService repoScans;
	@Mock RepoScanSettingsService repoScanSettings;
	private HomeDashboardService service;

	@BeforeEach
	void setUp() {
		service = new HomeDashboardService(metrics, pullRequests, uploads, images,
				prScanning, uploadScanning, imageScanning, scanRegistrationService,
				apiIntegrationService, repoScans, repoScanSettings);
	}

	@Test
	void recentActivityMergesBoundedModuleQueriesByCompletionTime() {
		PullRequestScanEntity pr = pullRequest("payments", "418", ScanStatus.DONE, 3000, 4000);
		UploadScanEntity upload = upload("SEC-21", "source.zip", ScanStatus.FAILED, 1000, 5000);
		ImageScanEntity image = image("api", "v2", ScanStatus.IN_PROGRESS, 6000, 0);
		when(pullRequests.findTop10ByOrderByEndDateDesc()).thenReturn(List.of(pr));
		when(uploads.findTop10ByOrderByEndDateDesc()).thenReturn(List.of(upload));
		when(images.findTop10ByOrderByEndDateDesc()).thenReturn(List.of(image));
		RepoScanEntity repoScan = repoScan("payments-api", "main", 7000, 9000);
		when(repoScans.latestFinished(10)).thenReturn(List.of(repoScan));

		List<HomeActivityItem> activity = service.getRecentActivity();

		assertEquals(List.of("Repository", "Upload", "PR", "Image"),
				activity.stream().map(HomeActivityItem::getModule).toList());
		assertEquals("payments-api@main", activity.get(0).getTarget());
		assertEquals("/reposcan/report/0", activity.get(0).getReportUrl());
		assertEquals("2.00 s", activity.get(0).getDuration());
		assertEquals(List.of("2H", "1L"), activity.get(0).getSeverityCounts().stream()
				.map(count -> count.getCompactText()).toList());
		assertEquals("source.zip · SEC-21", activity.get(1).getTarget());
		assertEquals("Failed", activity.get(1).getStatus().getLabel());
		assertEquals("4.00 s", activity.get(1).getDuration());
		assertNull(activity.get(3).getCompletedTime());
		assertEquals("Not recorded", activity.get(3).getDuration());
		verify(pullRequests).findTop10ByOrderByEndDateDesc();
		verify(uploads).findTop10ByOrderByEndDateDesc();
		verify(images).findTop10ByOrderByEndDateDesc();
	}

	@Test
	void moduleActivityFactoriesNormalizeIncompleteDatesAndReportTargets() {
		PullRequestScanEntity pr = pullRequest("payments", "418", ScanStatus.DONE, 3000, 4000);
		UploadScanEntity upload = upload("SEC-21", "source.zip", ScanStatus.FAILED, 1000, 0);
		ImageScanEntity image = image("api", "v2", ScanStatus.DONE, 2000, 3500);

		HomeActivityItem prItem = HomeActivityItem.fromPullRequest(pr);
		HomeActivityItem uploadItem = HomeActivityItem.fromUpload(upload);
		HomeActivityItem imageItem = HomeActivityItem.fromImage(image);

		assertEquals("payments #418", prItem.getTarget());
		assertEquals("/scan/report/0", prItem.getReportUrl());
		assertNull(uploadItem.getCompletedTime());
		assertEquals("Not recorded", uploadItem.getDuration());
		assertEquals("api:v2", imageItem.getTarget());
		assertEquals("1.50 s", imageItem.getDuration());
	}

	@Test
	void recentActivitySummarizesFindingsBySeverityInPriorityOrder() {
		ImageScanEntity image = image("api", "v2", ScanStatus.DONE, 2000, 3500);
		ImageViolationEntity high = new ImageViolationEntity();
		high.setSeverity(RulePriority.HIGH);
		ImageViolationEntity medium = new ImageViolationEntity();
		medium.setSeverity(RulePriority.MEDIUM);
		ImageViolationEntity secondMedium = new ImageViolationEntity();
		secondMedium.setSeverity(RulePriority.MEDIUM);
		image.setViolations(List.of(medium, high, secondMedium));

		HomeActivityItem item = HomeActivityItem.fromImage(image);

		assertEquals(List.of("1H", "2M"), item.getSeverityCounts().stream()
				.map(count -> count.getCompactText()).toList());
		assertEquals(List.of("1 High finding", "2 Medium findings"),
				item.getSeverityCounts().stream()
						.map(count -> count.getAccessibleText()).toList());
	}

	@Test
	void pullRequestActivitySeparatesManualReviewMatchesAndLinksToTheirReport() {
		var pr = pullRequest("payments", "418", ScanStatus.DONE, 3000, 4000);
		var finding = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity();
		finding.setViolationName("Unsafe operation"); finding.setSeverity(RulePriority.HIGH);
		var mcr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity();
		mcr.setViolationName("MCR Match: authentication"); mcr.setSeverity(RulePriority.INFORMATIONAL);
		org.springframework.test.util.ReflectionTestUtils.setField(pr, "violations", List.of(finding, mcr));
		var item = HomeActivityItem.fromPullRequest(pr);
		assertEquals(1, item.getFindingCount()); assertEquals(1, item.getMcrCount());
		assertEquals("/scan/mcr/report/0", item.getMcrReportUrl());
		assertEquals(List.of("1H"), item.getSeverityCounts().stream().map(count -> count.getCompactText()).toList());
	}

	@Test
	void overviewCombinesProjectionTotalsWithRecentFailureCounts() {
		when(metrics.getHomeMetrics(anyLong(), anyLong()))
				.thenReturn(new HomeMetricsSnapshot(14, 9, 2_500));
		when(pullRequests.countByStatusInAndSubmitDateBetween(anyList(), anyLong(), anyLong()))
				.thenReturn(2L);
		when(uploads.countByStatusInAndSubmitDateBetween(anyList(), anyLong(), anyLong()))
				.thenReturn(1L);
		when(images.countByStatusInAndSubmitDateBetween(anyList(), anyLong(), anyLong()))
				.thenReturn(3L);
		when(repoScans.countIncomplete(anyLong(), anyLong())).thenReturn(4L);

		HomeOverviewModel overview = service.getOverview();

		assertEquals(14, overview.getCompleted());
		assertEquals(10, overview.getFailedIncomplete());
		assertEquals(9, overview.getFindings());
		assertEquals("2.50 s", overview.getAverageDuration());
	}

	@Test
	void processorHealthReportsDegradedStateAndQueueTotals() {
		when(scanRegistrationService.getScannerNames()).thenReturn(List.of("ESLint"));
		when(uploadScanning.isPaused()).thenReturn(true);
		when(prScanning.getTaskNumInQueue()).thenReturn(2L);
		when(uploadScanning.getTaskNumInQueue()).thenReturn(3L);
		when(imageScanning.getTaskNumActive()).thenReturn(1L);

		when(repoScans.countScans(ScanStatus.NOT_STARTED)).thenReturn(40L);
		when(repoScans.countScans(ScanStatus.IN_PROGRESS)).thenReturn(1L);

		ProcessorHealthModel health = service.getProcessorHealth();

		assertEquals("Scanning paused", health.getLabel());
		assertEquals("warning", health.getTone());
		assertEquals(45, health.getQueued());
		assertEquals(2, health.getActive());
	}

	@Test
	void pausedRepositoryScansNeedAttention() {
		when(scanRegistrationService.getScannerNames()).thenReturn(List.of("Betterleaks"));
		when(repoScanSettings.isPaused()).thenReturn(true);

		assertEquals("Scanning paused", service.getProcessorHealth().getLabel());
	}

	@Test
	void processorHealthListsRegisteredScannersAndConfiguredConnections() {
		ApiIntegrationEntity bitbucket = org.mockito.Mockito.mock(ApiIntegrationEntity.class);
		ApiIntegrationEntity ecr = org.mockito.Mockito.mock(ApiIntegrationEntity.class);
		when(bitbucket.getApiLabel()).thenReturn("Bitbucket Cloud");
		when(ecr.getApiLabel()).thenReturn("Production ECR");
		when(scanRegistrationService.getScannerNames())
				.thenReturn(List.of("Advisory", "ESLint", "PMD"));
		when(apiIntegrationService.getAllSettings()).thenReturn(List.of(ecr, bitbucket));

		ProcessorHealthModel health = service.getProcessorHealth();

		assertEquals(List.of("Advisory", "ESLint", "PMD"), health.getScanners());
		assertEquals(List.of("Bitbucket Cloud", "Production ECR"), health.getConnections());
	}

	@Test
	void moduleStatusSeparatesReadyNeedsSetupAndOff() {
		var ready = org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner.class);
		var setup = org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner.class);
		var off = org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner.class);
		when(setup.setupIssue()).thenReturn("AWS Security Agent is disabled");
		when(off.isDisabled()).thenReturn(true);
		java.util.Map<String, com.tracelink.appsec.watchtower.core.module.scanner.IScanner<?, ?>> byModule =
				new java.util.LinkedHashMap<>();
		byModule.put("PMD", ready);
		byModule.put("AwsSecurityAgent", setup);
		byModule.put("Opengrep", off);
		when(scanRegistrationService.getScannersByModule()).thenReturn(byModule);
		when(scanRegistrationService.getScannerNames()).thenReturn(List.of("PMD", "AwsSecurityAgent", "Opengrep"));

		ProcessorHealthModel health = service.getProcessorHealth();

		assertEquals("Scanning on", health.getLabel());
		assertEquals(List.of("ready", "setup", "off"),
				health.getModules().stream().map(ModuleStatus::state).toList());
		assertEquals("AWS Security Agent", health.getModules().get(1).name());
		assertEquals("AWS Security Agent is disabled.", health.getModules().get(1).reason());
		assertEquals(1, health.countModules(ModuleStatus.OFF));
		org.mockito.Mockito.verify(off, org.mockito.Mockito.never()).setupIssue();
	}

	@Test
	void integrationStatusShowsConnectionAndWebhookWithoutTheRawError() {
		ApiIntegrationEntity ecr = org.mockito.Mockito.mock(ApiIntegrationEntity.class);
		when(ecr.getApiLabel()).thenReturn("Example");
		when(ecr.getApiType()).thenReturn(com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType.ECR);
		when(ecr.getHealthOk()).thenReturn(false);
		when(ecr.getRegisterState())
				.thenReturn(com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState.NOT_REGISTERED);
		when(apiIntegrationService.getAllSettings()).thenReturn(List.of(ecr));

		IntegrationStatus status = service.getProcessorHealth().getIntegrations().get(0);

		assertEquals("bad", status.connection());
		assertEquals("Failing", status.connectionText());
		assertEquals("Amazon ECR · images", status.provider());
		assertEquals("Webhook off", status.webhookText());
		org.mockito.Mockito.verify(ecr, org.mockito.Mockito.never()).getHealthError();
	}

	private static PullRequestScanEntity pullRequest(String repo, String id, ScanStatus status,
			long start, long end) {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		container.setRepoName(repo);
		container.setPrId(id);
		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(container);
		setTimes(scan, status, start, end);
		return scan;
	}

	private static RepoScanEntity repoScan(String repo, String branch, long start, long end) {
		RepositoryEntity repository = new RepositoryEntity();
		repository.setRepoName(repo);
		RepoScanEntity scan = new RepoScanEntity();
		scan.setRepository(repository);
		scan.setBranch(branch);
		scan.setStatus(ScanStatus.DONE);
		scan.setStartDate(start);
		scan.setEndDate(end);
		scan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH, RulePriority.LOW,
				RulePriority.HIGH)));
		return scan;
	}

	private static UploadScanEntity upload(String ticket, String name, ScanStatus status,
			long start, long end) {
		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setName(name);
		UploadScanEntity scan = new UploadScanEntity();
		scan.setContainer(container);
		setTimes(scan, status, start, end);
		return scan;
	}

	private static ImageScanEntity image(String repository, String tag, ScanStatus status,
			long start, long end) {
		ImageScanContainerEntity container = new ImageScanContainerEntity();
		container.setRepositoryName(repository);
		container.setTagName(tag);
		ImageScanEntity scan = new ImageScanEntity();
		scan.setContainer(container);
		setTimes(scan, status, start, end);
		return scan;
	}

	private static void setTimes(com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity<?, ?> scan,
			ScanStatus status, long start, long end) {
		scan.setStatus(status);
		scan.setSubmitDate(start - 100);
		scan.setStartDate(start);
		scan.setEndDate(end);
	}
}

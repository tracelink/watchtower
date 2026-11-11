package com.tracelink.appsec.watchtower.core.metrics;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanSettingsService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;
import com.tracelink.appsec.watchtower.core.scan.presentation.DurationText;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;

/** Composes the home page from durable projections and bounded per-module activity queries. */
@Service
public class HomeDashboardService {
	private static final int ACTIVITY_LIMIT = 10;
	private static final List<ScanStatus> INCOMPLETE_STATUSES = List.of(
			ScanStatus.FAILED, ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED);

	private final MetricsCacheService metrics;
	private final PRScanRepository pullRequests;
	private final UploadScanRepository uploads;
	private final ImageScanRepository images;
	private final PRScanningService prScanning;
	private final UploadScanningService uploadScanning;
	private final ImageScanningService imageScanning;
	private final ScanRegistrationService scanRegistration;
	private final ApiIntegrationService apiIntegrations;
	private final RepoScanViewService repoScans;
	private final RepoScanSettingsService repoScanSettings;

	public HomeDashboardService(MetricsCacheService metrics, PRScanRepository pullRequests,
			UploadScanRepository uploads, ImageScanRepository images,
			PRScanningService prScanning, UploadScanningService uploadScanning,
			ImageScanningService imageScanning, ScanRegistrationService scanRegistration,
			ApiIntegrationService apiIntegrations, RepoScanViewService repoScans,
			RepoScanSettingsService repoScanSettings) {
		this.metrics = metrics;
		this.pullRequests = pullRequests;
		this.uploads = uploads;
		this.images = images;
		this.prScanning = prScanning;
		this.uploadScanning = uploadScanning;
		this.imageScanning = imageScanning;
		this.scanRegistration = scanRegistration;
		this.apiIntegrations = apiIntegrations;
		this.repoScans = repoScans;
		this.repoScanSettings = repoScanSettings;
	}

	public ProcessorHealthModel getProcessorHealth() {
		List<String> scanners = scanRegistration.getScannerNames();
		List<String> connections = apiIntegrations.getAllSettings().stream()
				.map(integration -> integration.getApiLabel())
				.filter(label -> label != null && !label.isBlank())
				.sorted(String.CASE_INSENSITIVE_ORDER)
				.toList();
		boolean degraded = scanners.isEmpty() || prScanning.isPaused() || prScanning.isQuiesced()
				|| uploadScanning.isPaused() || uploadScanning.isQuiesced()
				|| imageScanning.isPaused() || imageScanning.isQuiesced()
				|| repoScanSettings.isPaused();
		long queued = prScanning.getTaskNumInQueue() + uploadScanning.getTaskNumInQueue()
				+ imageScanning.getTaskNumInQueue()
				+ repoScans.countScans(ScanStatus.NOT_STARTED);
		long active = prScanning.getTaskNumActive() + uploadScanning.getTaskNumActive()
				+ imageScanning.getTaskNumActive() + repoScans.countScans(ScanStatus.IN_PROGRESS);
		List<IntegrationStatus> integrations = apiIntegrations.getAllSettings().stream()
				.filter(integration -> integration.getApiLabel() != null && !integration.getApiLabel().isBlank())
				.sorted(Comparator.comparing(integration -> integration.getApiLabel(), String.CASE_INSENSITIVE_ORDER))
				.map(IntegrationStatus::from)
				.toList();
		return new ProcessorHealthModel(degraded ? "Scanning paused" : "Scanning on",
				degraded ? "warning" : "success", degraded ? "warning" : "check_circle",
				queued, active, scanners, connections, moduleStatuses(), integrations);
	}

	/** Each module from its execution policy and settings; no provider is contacted. */
	public List<ModuleStatus> getModuleStatuses() {
		return moduleStatuses();
	}

	private List<ModuleStatus> moduleStatuses() {
		List<ModuleStatus> modules = new ArrayList<>();
		scanRegistration.getScannersByModule()
				.forEach((module, scanner) -> modules.add(ModuleStatus.of(module, scanner)));
		return List.copyOf(modules);
	}

	public HomeOverviewModel getOverview() {
		long end = System.currentTimeMillis();
		long start = end - Duration.ofDays(30).toMillis();
		HomeMetricsSnapshot completed = metrics.getHomeMetrics(start, end);
		long failedIncomplete = countIncomplete(start, end);
		return new HomeOverviewModel(completed.completed(), failedIncomplete, completed.findings(),
				formatDuration(completed.averageDurationMillis()));
	}

	/** Scans submitted in the window that failed or never finished, across every scan type. */
	public long countIncomplete(long start, long end) {
		return pullRequests.countByStatusInAndSubmitDateBetween(INCOMPLETE_STATUSES, start, end)
				+ uploads.countByStatusInAndSubmitDateBetween(INCOMPLETE_STATUSES, start, end)
				+ images.countByStatusInAndSubmitDateBetween(INCOMPLETE_STATUSES, start, end)
				+ repoScans.countIncomplete(start, end);
	}

	public List<HomeActivityItem> getRecentActivity() {
		List<HomeActivityItem> items = new ArrayList<>();
		pullRequests.findTop10ByOrderByEndDateDesc().stream()
				.map(HomeActivityItem::fromPullRequest).forEach(items::add);
		uploads.findTop10ByOrderByEndDateDesc().stream()
				.map(HomeActivityItem::fromUpload).forEach(items::add);
		images.findTop10ByOrderByEndDateDesc().stream()
				.map(HomeActivityItem::fromImage).forEach(items::add);
		repoScans.latestFinished(ACTIVITY_LIMIT).stream()
				.map(HomeActivityItem::fromRepo).forEach(items::add);
		return items.stream()
				.sorted(Comparator.comparingLong(HomeActivityItem::getSortTime).reversed())
				.limit(ACTIVITY_LIMIT)
				.toList();
	}

	static String formatDuration(double millis) {
		return DurationText.of(millis);
	}

}

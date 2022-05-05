package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import ch.qos.logback.classic.Level;

/**
 * Manages creating scans for Images
 *
 * @author csmith
 */
@Service
public class ImageScanningService extends AbstractScanningService {

	private static final Logger LOG = LoggerFactory.getLogger(ImageScanningService.class);

	private final RepositoryService repoService;
	private final ScanRegistrationService scanRegistrationService;
	private final ApiIntegrationService apiService;
	private final LogsService logService;
	private final ImageScanResultService scanResultService;
	private final ImageAdvisoryService imageAdvisoryService;

	protected ImageScanningService(@Autowired RepositoryService repoService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired ApiIntegrationService apiService,
			@Autowired LogsService logService,
			@Autowired ImageScanResultService scanResultService,
			@Autowired ImageAdvisoryService imageAdvisoryService) {
		super(2, false);
		this.repoService = repoService;
		this.scanRegistrationService = scanRegistrationService;
		this.apiService = apiService;
		this.logService = logService;
		this.scanResultService = scanResultService;
		this.imageAdvisoryService = imageAdvisoryService;
	}

	/**
	 * Queue a new Scan onto the next available async thread.
	 *
	 * @param scan an object describing the image to review
	 * @throws RejectedExecutionException if the async manager cannot handle another task
	 * @throws ScanRejectedException      If the scan could not be started due to a configuration
	 *                                    problem
	 */
	public void doImageScan(ImageScan scan)
			throws RejectedExecutionException, ScanRejectedException {
		String imageName = scan.getScanName();
		if (isQuiesced()) {
			LOG.error("Quiesced. Did not schedule image scan: " + imageName);
			throw new ScanRejectedException("Quiesced. Did not schedule image: " + imageName);
		}
		RepositoryEntity registry = repoService
				.upsertRepo(ImageScanType.CONTAINER, scan.getApiLabel(), scan.getRepository());
		RulesetEntity ruleset = registry.getRuleset();

		// Skip scan if registry is not configured with a ruleset
		if (ruleset == null) {
			LOG.info("Image: " + imageName
					+ " skipped as the repository is not configured with a ruleset.");
			return;
		}

		// Skip scan if there are no scanners configured
		if (!scanRegistrationService.hasImageScanners()) {
			LOG.info("Image: " + imageName + " skipped as there are no scanners configured.");
			return;
		}
		ApiIntegrationEntity apiEntity = apiService.findByLabel(scan.getApiLabel());
		IImageApi api = (IImageApi) apiEntity.createApi();

		ImageScanAgent scanAgent = new ImageScanAgent(scan)
				.withApi(api)
				.withScanResultService(this.scanResultService)
				.withAdvisoryService(imageAdvisoryService)
				.withScanners(scanRegistrationService.getImageScanners())
				.withRuleset(ruleset.toDto())
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO));

		CompletableFuture.runAsync(scanAgent, getExecutor());
	}


	@Override
	protected void recoverFromDowntime() {
		// TBD
	}
}

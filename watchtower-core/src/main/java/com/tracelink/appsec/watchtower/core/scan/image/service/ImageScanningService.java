package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.registry.RegistryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.registry.RegistryService;

import ch.qos.logback.classic.Level;

@Service
public class ImageScanningService extends AbstractScanningService {
	private static Logger LOG = LoggerFactory.getLogger(ImageScanningService.class);

	private RegistryService registryService;

	private ScanRegistrationService scanRegistrationService;

	private APIIntegrationService apiService;

	private LogsService logService;

	protected ImageScanningService(int executorThreads, boolean shouldRecoverFromDowntime) {
		super(2, false);
	}

	public void doImageScan(ImageScan scan)
			throws RejectedExecutionException, ScanRejectedException, ApiIntegrationException {
		String imageName = scan.getScanName();
		if (isQuiesced()) {
			LOG.error("Quiesced. Did not schedule image scan: " + imageName);
			throw new ScanRejectedException("Quiesced. Did not schedule image: " + imageName);
		}
		RegistryEntity registry =
				registryService.upsertRegistry(scan.getApiLabel(), scan.getRegistryName());
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
		APIIntegrationEntity apiEntity = apiService.findByLabel(scan.getApiLabel());
		IImageApi api = (IImageApi) apiEntity.createApi();

		ImageScanAgent scanAgent = new ImageScanAgent(scan)
				.withApi(api)
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

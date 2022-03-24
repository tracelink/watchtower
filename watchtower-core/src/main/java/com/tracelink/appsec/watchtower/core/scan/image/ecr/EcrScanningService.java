package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiFactoryService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrApi;
import com.tracelink.appsec.watchtower.core.scan.image.ContainerImage;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import ch.qos.logback.classic.Level;

@Service
public class EcrScanningService extends AbstractScanningService {
	private static Logger LOG = LoggerFactory.getLogger(EcrScanningService.class);

	private ApiFactoryService apiFactory;
	private RepositoryService repoService;
	private APIIntegrationService apiIntegrationService;
	private ScanRegistrationService scanRegistrationService;
	private EcrScanResultService ecrScanResultService;
	private LogsService logService;

	public EcrScanningService(@Autowired ApiFactoryService apiFactory,
			@Autowired LogsService logService,
			@Autowired RepositoryService repoService,
			@Autowired EcrScanResultService ecrScanResultService,
			@Autowired ScanRegistrationService scanRegistrationService) {
		super(1, false);
		this.apiFactory = apiFactory;
		this.logService = logService;
		this.repoService = repoService;
		this.ecrScanResultService = ecrScanResultService;
		this.scanRegistrationService = scanRegistrationService;
	}

	/**
	 * Scan the incoming image
	 * 
	 * @param image the ECR Image to be scanned
	 * @throws ApiIntegrationException
	 */
	public void doEcrScan(ContainerImage image) throws ApiIntegrationException {
		RepositoryEntity repository = repoService
				.upsertRepo(image.getApiLabel(), image.getRepository());

		RulesetEntity allowlist = repository.getRuleset();
		if (allowlist == null) {
			// Skip scan if repository is not configured with a ruleset if (allowlist == null) {
			LOG.info("Image: " + image.getImageName() +
					" skipped as the repository is not configured with an allow list.");
			return;
		}

		APIIntegrationEntity apiIntegration =
				apiIntegrationService.findByEndpoint(image.getApiLabel());
		EcrApi api = (EcrApi) apiFactory
				.createApiForApiEntity(apiIntegration);

		// Create scan agent
		EcrScanAgent scanAgent = new EcrScanAgent(image.getImageName())
				.withApi(api)
				.withScanResultService(ecrScanResultService)
				.withRuleset(allowlist.toDto())
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO))
				.withImage(image)
				.withScanners(scanRegistrationService.getScanners(ImageScanConfig.class));

		CompletableFuture.runAsync(scanAgent, getExecutor());
	}


	/*
	 * TODO Can we even do this?
	 */
	@Override
	protected void recoverFromDowntime() {
		// TODO Auto-generated method stub

	}

}

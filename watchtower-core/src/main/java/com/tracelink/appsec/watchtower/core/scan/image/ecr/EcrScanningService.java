package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiFactoryService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrApi;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrImage;
import com.tracelink.appsec.watchtower.core.scan.image.ImageRepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.ImageRepositoryRepository;

@Service
public class EcrScanningService extends AbstractScanningService {
	private static Logger LOG = LoggerFactory.getLogger(EcrScanningService.class);

	private ApiFactoryService apiFactory;
	private ImageRepositoryRepository imageRepoRepository;
	private APIIntegrationService apiIntegrationService;

	private EcrScanResultService ecrScanResultService;

	public EcrScanningService(@Autowired ApiFactoryService apiFactory,
			@Autowired ImageRepositoryRepository imageRepoRepository,
			@Autowired EcrScanResultService ecrScanResultService) {
		super(1, false);
		this.apiFactory = apiFactory;
		this.imageRepoRepository = imageRepoRepository;
		this.ecrScanResultService = ecrScanResultService;
	}

	/**
	 * Scan the incoming image
	 * 
	 * @param image the ECR Image to be scanned
	 * @throws ApiIntegrationException
	 */
	public void doEcrScan(EcrImage image) throws ApiIntegrationException {
		ImageRepositoryEntity repository = imageRepoRepository
				.upsertRepository(image.getAccountId(), image.getRepository());

		RulesetEntity allowlist = repository.getRuleset();
		if (allowlist == null) {
			// Skip scan if repository is not configured with a ruleset if (allowlist == null) {
			LOG.info("Image: " + image.getImageName() +
					" skipped as the repository is not configured with an allow list.");
			return;
		}

		APIIntegrationEntity apiIntegration =
				apiIntegrationService.findByEndpoint(image.getAccountId());
		EcrApi api = (EcrApi) apiFactory
				.createApiForApiEntity(apiIntegration);

		// Create scan agent
		EcrScanAgent scanAgent = new EcrScanAgent(image.getImageName())
				.withApi(api)
				.withScanResultService(ecrScanResultService)
				.withRuleset(allowlist.toDto());

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

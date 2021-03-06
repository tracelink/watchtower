package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The Synchronizer is used to check back against all SCMs for all unresolved PRs to see if the PRs
 * have been declined or superceded or otherwise "resolved"
 *
 * @author csmith
 */
@Component
public class PullRequestSynchronizer {

	private static final Logger LOG = LoggerFactory.getLogger(PullRequestSynchronizer.class);
	private static final String SKIP_DEV_PROFILE = "dev";

	private final Environment environment;
	private final PRContainerRepository prRepo;
	private final PRScanResultService prResultService;
	private final ApiIntegrationService apiIntegrationService;

	public PullRequestSynchronizer(
			@Autowired Environment environment,
			@Autowired PRContainerRepository prRepo,
			@Autowired PRScanResultService prResultService,
			@Autowired ApiIntegrationService apiIntegrationService) {
		this.environment = environment;
		this.prRepo = prRepo;
		this.prResultService = prResultService;
		this.apiIntegrationService = apiIntegrationService;
	}

	/**
	 * Sync data from the remove SCMs
	 */
	@Scheduled(initialDelay = 1000L * 60, fixedRate = 1000L * 60 * 60 * 3)
	public void syncData() {
		if (environment.acceptsProfiles(Profiles.of(SKIP_DEV_PROFILE))) {
			LOG.info("Skipping Data Sync. Server started in Dev Mode.");
			return;
		}
		LOG.info("Beginning Data Sync to resolve Pull Requests");
		if (apiIntegrationService.getAllSettings().isEmpty()) {
			LOG.info("Skipping Data Sync. No API Settings Found");
			return;
		}
		int numResolved = 0;
		int numUnresolved = 0;
		int page = 0;
		Page<PullRequestContainerEntity> prPage;
		do {
			prPage = prRepo.findByResolvedFalse(PageRequest.of(page, 100));
			numUnresolved += prPage.getNumberOfElements();
			for (PullRequestContainerEntity entity : prPage) {
				try {
					PullRequest pr = entity.toPullRequest();
					ApiIntegrationEntity apiEntity =
							apiIntegrationService.findByLabel(pr.getApiLabel());
					IScmApi api = (IScmApi) apiEntity.createApi();
					PullRequest filledPR = api.updatePRData(pr);
					if (filledPR.getState() == PullRequestState.DECLINED) {
						prResultService.markPrResolved(filledPR);
						numResolved++;
					}

				} catch (ScanRejectedException e) {
					LOG.error("Error while creating api for data sync", e);
				}
			}
			page++;
		} while (!prPage.isLast());

		LOG.info("Pull Request Data Sync complete. " + numUnresolved + " initially unresolved. "
				+ numResolved + " resolved during sync.");
	}
}

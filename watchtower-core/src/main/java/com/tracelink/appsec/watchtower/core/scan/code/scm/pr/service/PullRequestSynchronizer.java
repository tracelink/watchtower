package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;

/**
 * The Synchronizer is used to check back against all SCMs for all unresolved PRs to see if the PRs
 * have been declined or superceded or otherwise "resolved"
 * 
 * @author csmith
 *
 */
@Component
public class PullRequestSynchronizer {
	private static Logger LOG = LoggerFactory.getLogger(PullRequestSynchronizer.class);

	private PRContainerRepository prRepo;

	private PRScanResultService prResultService;

	private APIIntegrationService apiIntegrationService;

	public PullRequestSynchronizer(@Autowired PRContainerRepository prRepo,
			@Autowired PRScanResultService prResultService,
			@Autowired APIIntegrationService apiIntegrationService) {
		this.prRepo = prRepo;
		this.prResultService = prResultService;
		this.apiIntegrationService = apiIntegrationService;
	}

	/**
	 * Sync data from the remove SCMs
	 */
	@Scheduled(initialDelay = 1000L * 60, fixedRate = 1000L * 60 * 60 * 3)
	public void syncData() {
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
					APIIntegrationEntity apiEntity =
							apiIntegrationService.findByLabel(pr.getApiLabel());
					IScmApi api = (IScmApi) apiEntity.createApi();
					PullRequest filledPR = api.updatePRData(pr);
					if (filledPR.getState() == PullRequestState.DECLINED) {
						prResultService.markPrResolved(filledPR);
						numResolved++;
					}

				} catch (ScanRejectedException | ApiIntegrationException e) {
					LOG.error("Error while creating api for data sync", e);
				}
			}
			page++;
		} while (!prPage.isLast());

		LOG.info("Pull Request Data Sync complete. " + numUnresolved + " initially unresolved. "
				+ numResolved + " resolved during sync.");
	}
}

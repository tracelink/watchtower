package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import ch.qos.logback.classic.Level;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Manages creating scans for Pull Requests
 *
 * @author csmith
 */
@Service
public class PRScanningService extends AbstractScanningService {

	private static final Logger LOG = LoggerFactory.getLogger(PRScanningService.class);

	private final LogsService logService;
	private final RepositoryService repoService;
	private final PRScanResultService prScanResultService;
	private final ScanRegistrationService scanRegistrationService;
	private final ApiIntegrationService apiService;

	public PRScanningService(
			@Autowired LogsService logService,
			@Autowired RepositoryService repoService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired ApiIntegrationService apiService,
			@Value("${watchtower.threads.prscan:4}") int threads,
			@Value("${watchtower.runAfterStartup:true}") boolean recoverFromDowntime) {
		super(threads, recoverFromDowntime);
		this.logService = logService;
		this.repoService = repoService;
		this.prScanResultService = prScanResultService;
		this.scanRegistrationService = scanRegistrationService;
		this.apiService = apiService;
	}

	/**
	 * Queue a new Scan onto the next available async thread.
	 *
	 * @param pr an object describing the pull request to review
	 * @throws RejectedExecutionException if the async manager cannot handle another task
	 * @throws ScanRejectedException      If the scan could not be started due to a configuration
	 *                                    problem
	 */
	public void doPullRequestScan(PullRequest pr)
			throws RejectedExecutionException, ScanRejectedException {
		String prName = pr.getPRString();
		if (isQuiesced()) {
			LOG.error("Quiesced. Did not schedule PR: " + prName);
			throw new ScanRejectedException("Quiesced. Did not schedule PR: " + prName);
		}

		RepositoryEntity repo = repoService.upsertRepo(CodeScanType.PULL_REQUEST, pr.getApiLabel(),
				pr.getRepoName());
		RulesetEntity ruleset = repo.getRuleset();

		// Skip scan if repository is not configured with a ruleset
		if (ruleset == null) {
			LOG.info("PR: " + prName
					+ " skipped as the repository is not configured with a ruleset.");
			return;
		}

		// Skip scan if there are no scanners configured
		if (!scanRegistrationService.hasCodeScanners()) {
			LOG.info("PR: " + prName + " skipped as there are no scanners configured.");
			return;
		}
		ApiIntegrationEntity apiEntity = apiService.findByLabel(pr.getApiLabel());
		IScmApi api = (IScmApi) apiEntity.createApi();
		pr = api.updatePRData(pr);

		// Create scan agent
		PRScanAgent scanAgent = new PRScanAgent(pr)
				.withApi(api)
				.withScanResultService(prScanResultService)
				.withScanners(scanRegistrationService.getCodeScanners())
				.withRuleset(ruleset.toDto())
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO));

		CompletableFuture.runAsync(scanAgent, getExecutor());
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * This will attempt to recover all PRs not scanned in each repository the system knows about
	 * for every SCM connection. If it detects repositories no longer available, it will disable
	 * them and not check for Pull Requests
	 */
	@Override
	protected void recoverFromDowntime() {
		List<PullRequest> prs = new ArrayList<>();
		Map<String, List<RepositoryEntity>> repoMap = repoService
				.getAllRepos(CodeScanType.PULL_REQUEST);
		for (ApiIntegrationEntity entity : apiService.getAllSettings()) {
			// Only recover if API integration is configured for pull request scans
			if (!entity.getScanType().equals(CodeScanType.PULL_REQUEST)) {
				continue;
			}
			LOG.debug("Recovering using API " + entity.getApiLabel());
			List<PullRequest> recovered = recoverByApi(repoMap, entity);
			prs.addAll(recovered);
		}
		if (!prs.isEmpty()) {
			LOG.info("Need to scan " + prs.size() + " Pull Requests after downtime");
			for (PullRequest pr : prs) {
				try {
					doPullRequestScan(pr);
				} catch (Exception e) {
					LOG.error("Could not submit recovery scan " + pr.getPRString(), e);
				}
			}
		} else {
			LOG.info("No Pull Requests found to recover after downtime");
		}
	}

	private List<PullRequest> recoverByApi(Map<String, List<RepositoryEntity>> repoMap,
			ApiIntegrationEntity entity) {
		List<PullRequest> prs = new ArrayList<>();
		IScmApi api = (IScmApi) entity.createApi();
		List<RepositoryEntity> repos =
				repoMap.getOrDefault(entity.getApiLabel(), new ArrayList<>());
		for (RepositoryEntity repo : repos) {
			if (!repo.isEnabled()) {
				continue;
			}
			String repoName = repo.getRepoName();
			if (!api.isRepositoryActive(repoName)) {
				LOG.info("Disabling dead repository " + repoName);
				repoService.disableRepository(repo);
			} else {
				LOG.debug("Recovering Repo " + repoName);
				List<PullRequest> recovered = recoverByRepo(entity, api, repo);
				prs.addAll(recovered);
			}
		}
		return prs;
	}

	private List<PullRequest> recoverByRepo(ApiIntegrationEntity entity, IScmApi api,
			RepositoryEntity repo) {
		long repoLastReview = repo.getLastReviewedDate();
		List<PullRequest> prUpdates = api.getOpenPullRequestsForRepository(repo.getRepoName())
				.stream().filter(pr -> {
					LOG.debug("Working on pr: " + pr.getPrId());
					try {
						PullRequestContainerEntity prEntity =
								prScanResultService.getPullRequestByLabelRepoAndId(
										entity.getApiLabel(), repo.getRepoName(), pr.getPrId());

						// This is an ancient pr and older than our last check on the repository.
						if (repoLastReview > pr.getUpdateTime()) {
							return false;
						}
						// if we haven't seen this PR add it
						if (prEntity == null) {
							return true;
						}
						// if we have seen it, but reviewed it before its last update, add it
						if (prEntity.getLastReviewedDate() < pr.getUpdateTime()) {
							return true;
						}
					} catch (Exception e) {
						LOG.error("Exception while trying to recover " + pr.getPRString(), e);
					}
					// otherwise we've seen it and reviewed it after the last update, so skip
					return false;
				}).collect(Collectors.toList());

		LOG.debug("Found " + prUpdates.size() + " prs since "
				+ repo.getLastReviewedDateAsDate());

		return prUpdates;
	}
}

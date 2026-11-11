package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

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

	// How recently a PR must have been reviewed to be skipped this cycle. Now that merged PRs
	// resolve on their own (5.0) and most resolution happens instantly via webhook (5.1), a PR
	// synced moments ago has nothing new to learn from another sync this soon.
	private static final long REVIEW_COOLDOWN_MILLIS = 1000L * 60 * 60 * 6;

	// How often the scheduler wakes to check whether a sync is due. The sync itself runs at the configured
	// frequency, which can be as short as the settings allow (a few minutes).
	static final long TICK_MILLIS = 1000L * 60 * 5;

	// How long a repo can go without activity before its PRs are skipped entirely. An
	// abandoned/disabled repo's PRs will never resolve via webhook either, so polling them on
	// the same cadence as active repos is pure waste.
	private static final long REPO_INACTIVITY_MILLIS = 1000L * 60 * 60 * 24 * 7;

	private final Environment environment;
	private final PRContainerRepository prRepo;
	private final PRScanResultService prResultService;
	private final ApiIntegrationService apiIntegrationService;
	private final RepositoryRepository repoRepo;
	private final PullRequestSyncSettingsService syncSettingsService;

	public PullRequestSynchronizer(
			@Autowired Environment environment,
			@Autowired PRContainerRepository prRepo,
			@Autowired PRScanResultService prResultService,
			@Autowired ApiIntegrationService apiIntegrationService,
			@Autowired RepositoryRepository repoRepo,
			@Autowired PullRequestSyncSettingsService syncSettingsService) {
		this.environment = environment;
		this.prRepo = prRepo;
		this.prResultService = prResultService;
		this.apiIntegrationService = apiIntegrationService;
		this.repoRepo = repoRepo;
		this.syncSettingsService = syncSettingsService;
	}

	/**
	 * Sync data from the remove SCMs. Ticks every five minutes, but the actual sync cadence is governed by
	 * the admin-configurable {@link PullRequestSyncSettingsEntity#getSyncFrequencyMinutes()} - see
	 * the due-check below. This is the same "fixed frequent tick, self-check against a
	 * persisted period" pattern already used by {@code KeyRotationService#autoRotateKeys()},
	 * chosen over a custom {@code SchedulingConfigurer}/{@code Trigger} because it needs no new
	 * Spring scheduling abstraction and survives an app restart (the "last sync" state lives in
	 * the database, not in an in-memory scheduler timer).
	 */
	@Scheduled(initialDelay = 1000L * 60, fixedRate = TICK_MILLIS)
	@SchedulerLock(name = "pr-sync", lockAtMostFor = "PT55M", lockAtLeastFor = "PT1M")
	public void syncData() {
		if (environment.acceptsProfiles(Profiles.of(SKIP_DEV_PROFILE))) {
			LOG.info("Skipping Data Sync. Server started in Dev Mode.");
			return;
		}
		PullRequestSyncSettingsEntity settings = syncSettingsService.getSettings();
		long now = System.currentTimeMillis();
		long intervalMillis = TimeUnit.MINUTES.toMillis(settings.getSyncFrequencyMinutes());
		Long lastSyncCompletedAt = settings.getLastSyncCompletedAt();
		if (lastSyncCompletedAt != null && now - lastSyncCompletedAt < intervalMillis) {
			LOG.debug("Skipping Data Sync. Next sync not due for another "
					+ (intervalMillis - (now - lastSyncCompletedAt)) / 1000 + "s.");
			return;
		}
		LOG.info("Beginning Data Sync to resolve Pull Requests");
		// Even when the final integration was deleted, its saved PRs need closing out.
		// Skip pull requests reviewed more recently than one sync ago, but never for longer than the old six hours:
		// with a sync every few minutes, a pull request that is open for less than six hours must still be checked.
		long reviewCutoff = now - Math.min(REVIEW_COOLDOWN_MILLIS, intervalMillis);
		long repoStaleCutoff = now - REPO_INACTIVITY_MILLIS;
		Set<String> staleRepoKeys = repoRepo.findByLastReviewedDateBefore(repoStaleCutoff)
				.stream()
				.map(PullRequestSynchronizer::repoKey)
				.collect(Collectors.toSet());

		int numResolved = 0;
		int numMerged = 0;
		int numDeclined = 0;
		int numUnresolved = 0;
		int numUnresolvable = 0;
		int numFailed = 0;
		int numSkippedStaleRepo = 0;
		long lastId = 0;
		Slice<PullRequestContainerEntity> prPage;
		do {
			// Offset pages skip rows as this loop removes resolved PRs from the query.
			prPage = prRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
					reviewCutoff, lastId, PageRequest.of(0, 100));
			numUnresolved += prPage.getNumberOfElements();
			for (PullRequestContainerEntity entity : prPage) {
				try {
					PullRequest pr = entity.toPullRequest();
					ApiIntegrationEntity apiEntity =
							apiIntegrationService.findByLabel(pr.getApiLabel());
					if (apiEntity == null) {
						// Permanent until somebody re-creates that integration. Retrying
						// every cycle forever costs a query and achieves nothing.
						resolveUnsyncable(entity, "its API integration '" + pr.getApiLabel()
								+ "' no longer exists");
						numUnresolvable++;
						continue;
					}
					if (staleRepoKeys.contains(repoKey(entity))) {
						// Skip SCM calls for inactive repos only after orphan cleanup.
						numSkippedStaleRepo++;
						continue;
					}
					IScmApi api = (IScmApi) apiEntity.createApi();
					PullRequest filledPR = api.updatePRData(pr);
					if (filledPR.getState().isResolved()) {
						prResultService.markPrResolved(filledPR);
						numResolved++;
						if (filledPR.getState() == PullRequestState.MERGED) {
							numMerged++;
						} else {
							numDeclined++;
						}
						LOG.debug("Resolved " + entity.getRepoName() + "-" + entity.getPrId()
								+ " as " + filledPR.getState());
					}

				} catch (PullRequestNotFoundException e) {
					// The Pull Request is gone from the SCM, or its recorded id was never
					// valid. Either way no future sync can learn anything about it, so take
					// it out of the unresolved set rather than re-fetching it forever.
					resolveUnsyncable(entity, "the SCM reports it does not exist");
					numUnresolvable++;
				} catch (ScanRejectedException e) {
					// Transient: a timeout, a rate limit, an SCM hiccup. Left unresolved on
					// purpose so the next cycle retries it. Logged as one concise line
					// rather than a stack trace, because this can recur for many PRs on
					// every cycle and a full dump per PR floods the logs.
					numFailed++;
					LOG.warn("Could not sync PR data for " + entity.getRepoName() + "-"
							+ entity.getPrId() + ": " + e.getMessage());
					LOG.debug("Sync failure detail", e);
				} catch (RuntimeException e) {
					// One bad row - a data error, an unexpected SCM reply - must not end the
					// run. Escaping here skipped every later PR and never recorded the sync,
					// so each hourly tick retried and failed on the same row.
					numFailed++;
					LOG.error("Could not sync PR data for " + entity.getRepoName() + "-"
							+ entity.getPrId() + ": " + e, e);
				}
			}
			if (prPage.hasContent()) lastId = prPage.getContent().getLast().getId();
		} while (prPage.hasNext());

		syncSettingsService.recordSyncCompleted(now);

		// The merged count is the signal that merged Pull Requests are now leaving the
		// unresolved set. On the first sync after that fix it drains the whole backlog,
		// so expect a large number once and small numbers thereafter.
		LOG.info("Pull Request Data Sync complete. " + numUnresolved + " initially unresolved. "
				+ numResolved + " resolved during sync (" + numMerged + " merged, "
				+ numDeclined + " declined). " + numUnresolvable
				+ " closed as unsyncable. " + numFailed + " failed to sync (will retry). "
				+ numSkippedStaleRepo + " skipped (repo inactive > 7d).");
	}

	private static String repoKey(PullRequestContainerEntity entity) {
		return repoKey(entity.getApiLabel(), entity.getRepoName());
	}

	private static String repoKey(RepositoryEntity entity) {
		return repoKey(entity.getApiLabel(), entity.getRepoName());
	}

	private static String repoKey(String apiLabel, String repoName) {
		return apiLabel + "\u0000" + repoName;
	}

	/**
	 * Takes a Pull Request out of the unresolved set because no future sync can succeed
	 * for it.
	 * <p>
	 * Applies to a Pull Request the SCM no longer has, and to one whose API integration
	 * has been deleted. Both used to be retried on every cycle indefinitely: the
	 * unresolved set only grew, and each member cost one SCM call every few hours for the
	 * lifetime of the install.
	 * <p>
	 * Marking it resolved is the honest reading - a Pull Request the SCM cannot produce
	 * is finished, whatever the reason - and needs no extra column.
	 *
	 * @param entity the Pull Request to close out
	 * @param reason why it can never sync, for the log
	 */
	private void resolveUnsyncable(PullRequestContainerEntity entity, String reason) {
		LOG.info("Closing " + entity.getRepoName() + "-" + entity.getPrId()
				+ " as unsyncable: " + reason + ". It will no longer be re-polled.");
		prResultService.markPrResolved(entity.toPullRequest());
	}
}

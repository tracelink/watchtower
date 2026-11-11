package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Handles logic around SCM repositories and their rulesets
 *
 * @author csmith, mcool
 */
@Service
public class RepositoryService {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryService.class);

	/**
	 * A repository slug as Bitbucket allows it, and not "." or "..": nothing else reaches an SCM
	 * URL.
	 */
	private static final Pattern SLUG = Pattern.compile("(?!\\.+$)[A-Za-z0-9._-]{1,128}");

	private RepositoryRepository repoRepo;

	private RulesetService rulesetService;

	private final RepositoryStatusService statuses;

	private final RepoScanRepository scans;

	private final RepoCatalogDao catalog;

	private final ApiIntegrationService integrations;

	public RepositoryService(@Autowired RepositoryRepository repoRepo,
			@Autowired RulesetService rulesetService, RepositoryStatusService statuses,
			RepoScanRepository scans, RepoCatalogDao catalog,
			ApiIntegrationService integrations) {
		this.repoRepo = repoRepo;
		this.rulesetService = rulesetService;
		this.statuses = statuses;
		this.scans = scans;
		this.catalog = catalog;
		this.integrations = integrations;
	}

	/**
	 * What a person can change about a repository. A null field is left as it is; a blank team
	 * or owner clears it; labels replace the current ones.
	 *
	 * @param rulesetId      the pull request ruleset, -1 for none
	 * @param team           the owning team
	 * @param owner          the owning person
	 * @param labels         labels, comma or space separated
	 * @param criticality    1 (critical) to 4 (low)
	 * @param scanningPaused true to stop scanning its pull requests and skip it in plans
	 */
	public record RepoEdit(Long rulesetId, String team, String owner, String labels,
			Integer criticality, Boolean scanningPaused) {
	}

	/**
	 * Changes one repository.
	 *
	 * @throws IllegalArgumentException if the repository is unknown or a value is not valid
	 * @throws RulesetNotFoundException if the ruleset does not exist
	 * @throws RulesetException         if it is a supporting ruleset
	 */
	@Transactional
	public RepositoryEntity update(long id, RepoEdit edit)
			throws RulesetNotFoundException, RulesetException {
		rulesetService.lockConfiguration();
		RepositoryEntity repo = repoRepo.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("Unknown repository"));
		applyEdit(repo, edit);
		return repoRepo.save(repo);
	}

	/**
	 * @return the repository, if it exists
	 */
	public Optional<RepositoryEntity> find(long id) {
		return repoRepo.findById(id);
	}

	private void applyEdit(RepositoryEntity repo, RepoEdit edit)
			throws RulesetNotFoundException, RulesetException {
		if (edit.rulesetId() != null) {
			repo.setRuleset(primaryRuleset(edit.rulesetId()));
		}
		if (edit.team() != null) {
			repo.setTeam(StringUtils.trimToNull(checkLength(edit.team().trim(), 128, "Team")));
		}
		if (edit.owner() != null) {
			repo.setOwnerName(StringUtils.trimToNull(checkLength(edit.owner().trim(), 255,
					"Owner")));
		}
		if (edit.labels() != null) {
			repo.setLabels(RepoLabels.split(edit.labels()));
		}
		if (edit.criticality() != null) {
			repo.setCriticality(RepoCriticality.of(edit.criticality()).getLevel());
		}
		if (edit.scanningPaused() != null) {
			repo.setScanningPaused(edit.scanningPaused());
		}
	}

	private RulesetEntity primaryRuleset(long rulesetId)
			throws RulesetNotFoundException, RulesetException {
		RulesetEntity ruleset = rulesetId == -1L ? null : rulesetService.getRuleset(rulesetId);
		if (ruleset != null && ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING)) {
			throw new RulesetException(
					"Cannot assign a supporting ruleset to a repository. Please select a primary ruleset.");
		}
		return ruleset;
	}

	/**
	 * Pauses or resumes scanning of many repositories: a paused repository's pull requests are
	 * not scanned and plans skip it.
	 *
	 * @param repoIds the repositories, at most {@value #MAX_BULK}
	 * @return how many repositories changed
	 */
	public int setPaused(List<Long> repoIds, boolean paused) {
		checkBulkSize(repoIds);
		return repoRepo.setScanningPaused(repoIds, paused);
	}

	/**
	 * How a delete went.
	 *
	 * @param deleted repositories deleted, with their repository scans
	 * @param busy    repositories left alone because a scan of them is queued or running
	 */
	public record DeleteResult(int deleted, int busy) {
	}

	/**
	 * Deletes repositories and their repository scan history. Pull request scans stay (they are
	 * kept by repository name), and a later webhook or sync adds a repository back with the
	 * default ruleset. Reports in S3 expire under the bucket's lifecycle rule; plans that named
	 * a repository by id simply stop matching it. A repository with a queued or running scan is
	 * left alone, so no worker meets a row that vanished under it.
	 *
	 * @param repoIds the repositories, at most {@value #MAX_BULK}
	 * @param user    who asked, for the log
	 * @return what was deleted
	 */
	@Transactional
	public DeleteResult delete(List<Long> repoIds, String user) {
		checkBulkSize(repoIds);
		List<Long> busy = scans.findRepositoriesBeingScanned(repoIds,
				List.of(ScanStatus.NOT_STARTED, ScanStatus.IN_PROGRESS));
		List<Long> doomed = repoIds.stream().distinct().filter(id -> !busy.contains(id))
				.toList();
		if (doomed.isEmpty()) {
			return new DeleteResult(0, busy.size());
		}
		int scanRows = scans.deleteByRepositoryIds(doomed);
		List<RepositoryEntity> repos = repoRepo.findAllById(doomed);
		repoRepo.deleteAllInBatch(repos);
		LOG.info("{} deleted {} repositories and their {} repository scans", user, repos.size(),
				scanRows);
		return new DeleteResult(repos.size(), busy.size());
	}

	/**
	 * @return every repository of an integration (any scan type), to delete with it; callers
	 *         delete them {@value #MAX_BULK} at a time through {@link #delete(List, String)}
	 */
	public List<Long> idsOfIntegration(String apiLabel) {
		return repoRepo.findIdsByApiLabel(apiLabel);
	}

	/**
	 * @return how many repositories each integration (api label) has
	 */
	public Map<String, Long> countsByIntegration() {
		// Keyed ignoring case: MySQL groups "bitbucket" and "Bitbucket" together but may name
		// the group either way, and the page looks it up by the integration's own spelling
		return repoRepo.countByApiLabel().stream().collect(Collectors.toMap(
				row -> (String) row[0], row -> (Long) row[1], Long::sum,
				() -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));
	}

	/**
	 * @return the name of the only repository of each integration that has exactly one, keyed by
	 *         api label ignoring case (as {@link #countsByIntegration()})
	 */
	public Map<String, String> onlyRepositoryByIntegration() {
		Map<String, String> names = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		for (Object[] row : repoRepo.firstNameByApiLabel()) {
			if (row[0] != null && ((Long) row[2]) == 1L) {
				names.put((String) row[0], (String) row[1]);
			}
		}
		return names;
	}

	/**
	 * @return the ids of every repository the filter matches, for "all matching" changes
	 */
	public List<Long> matchingIds(ScanType type, String apiLabel, RepositoryFilter filter) {
		return repoRepo.findAll(statuses.matching(type, apiLabel, filter)).stream()
				.map(RepositoryEntity::getId).toList();
	}

	/**
	 * Adds a repository the integration can see, before any pull request or sync: one read from
	 * the SCM, then the same insert a sync makes (default ruleset), then the person's values.
	 *
	 * @param apiLabel the source code integration
	 * @param slug     the repository's slug
	 * @param edit     values to set on it
	 * @return the repository
	 * @throws IllegalArgumentException if the slug is not a plain name, the integration is not a
	 *                                  source code integration, or it has no such repository
	 */
	@Transactional(rollbackFor = Exception.class)
	public RepositoryEntity addManually(String apiLabel, String slug, RepoEdit edit)
			throws RulesetNotFoundException, RulesetException {
		String name = StringUtils.trimToEmpty(slug);
		if (!SLUG.matcher(name).matches()) {
			throw new IllegalArgumentException(
					"A repository slug is letters, digits, dots, hyphens and underscores");
		}
		ApiIntegrationEntity integration = integrations.findByLabel(apiLabel);
		if (integration == null
				|| !CodeScanType.PULL_REQUEST.equals(integration.getScanType())) {
			throw new IllegalArgumentException("Unknown source code integration");
		}
		Optional<ScmRepository> listed;
		try {
			listed = ((IScmApi) integration.createApi()).getRepository(name);
		} catch (RuntimeException e) {
			LOG.warn("Could not read repository {} of {}", name, apiLabel, e);
			throw new IllegalArgumentException("Could not read the repository from " + apiLabel);
		}
		ScmRepository found = listed.orElseThrow(() -> new IllegalArgumentException(
				apiLabel + " has no repository named " + name));
		rulesetService.lockConfiguration();
		RulesetEntity defaultRuleset = rulesetService.getDefaultRuleset();
		catalog.upsertPage(apiLabel, List.of(found),
				defaultRuleset == null ? null : defaultRuleset.getId(),
				System.currentTimeMillis());
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, found.slug());
		if (repo == null) {
			throw new IllegalArgumentException("Could not add " + found.slug());
		}
		applyEdit(repo, edit);
		return repoRepo.save(repo);
	}

	/**
	 * One page of the repository inventory.
	 *
	 * @param type     the scan type
	 * @param apiLabel the integration, or null for every integration of the type
	 * @param filter   name, status, label, team and project
	 * @param pageable page and sort
	 * @return the matching page
	 */
	public Page<RepositoryEntity> list(ScanType type, String apiLabel, RepositoryFilter filter,
			Pageable pageable) {
		return repoRepo.findAll(statuses.matching(type, apiLabel, filter), pageable);
	}

	/**
	 * get all repos for all Api Labels using the given scan type
	 *
	 * @param type the scan type to get repos for
	 * @return a Map of each Api Label to a list of their known repos, keyed ignoring case as the
	 *         database matches labels: rows stored under "bitbucket" (V007 renamed the label
	 *         everywhere but here) belong to the "Bitbucket" integration
	 */
	public Map<String, List<RepositoryEntity>> getAllRepos(ScanType type) {
		return repoRepo.findByScanType(type).stream().collect(Collectors.groupingBy(
				RepositoryEntity::getApiLabel, () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER),
				Collectors.toList()));
	}

	/**
	 * @param type the scan type
	 * @return every integration (api label) with repositories of this type, sorted
	 */
	public List<String> getApiLabels(ScanType type) {
		return repoRepo.findApiLabelsByScanType(type);
	}

	/**
	 * Tie a ruleset entity to a repository under an Api Label
	 *
	 * @param rulesetId ID of the ruleset to use
	 * @param apiLabel  the Api that can talk to the repo
	 * @param repoName  which repo to configure
	 * @throws RulesetNotFoundException if the ruleset doesn't exist or the apiLabel is unknown
	 * @throws RulesetException         if a non-primary ruleset is being assigned to a repo
	 * @throws ApiIntegrationException  if the apiLabel is unknown
	 */
	@Transactional(rollbackFor = Exception.class)
	public void setRulesetForRepo(long rulesetId, String apiLabel, String repoName)
			throws RulesetNotFoundException,
			RulesetException, ApiIntegrationException {
        rulesetService.lockConfiguration();
		RulesetEntity ruleset = rulesetId == -1L ? null : rulesetService.getRuleset(rulesetId);
		// Check that this is a primary ruleset
		if (ruleset != null && ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING)) {
			throw new RulesetException(
					"Cannot assign a supporting ruleset to a repository. Please select a primary ruleset.");
		}
		rulesetService.lockConfiguration();
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, repoName);
		if (repo == null) {
			throw new ApiIntegrationException("Unknown API label");
		}
		repo.setRuleset(ruleset);
		repoRepo.saveAndFlush(repo);
	}

	/**
	 * The repository as stored, without creating or touching it. A request that is only being
	 * queued must not add a row for a repository nobody has scanned yet.
	 *
	 * @param apiLabel the api label of the integration
	 * @param repoName the repository name
	 * @return the stored repository, or empty when it is not known yet
	 */
	public Optional<RepositoryEntity> findExisting(String apiLabel, String repoName) {
		return Optional.ofNullable(repoRepo.findByApiLabelAndRepoName(apiLabel, repoName));
	}

	/**
	 * Update/Insert a repository using the api label and default ruleset. Ensures the repository is
	 * in the enabled state
	 *
	 * @param type     the repository type
	 * @param apiLabel the api label to add this repo name to
	 * @param repoName the new repository name
	 * @return the upserted Respository information
	 */
	@Transactional
	public RepositoryEntity upsertRepo(ScanType type, String apiLabel, String repoName) {
		rulesetService.lockConfiguration();
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, repoName);
		if (repo == null) {
			repo = new RepositoryEntity();
			repo.setApiLabel(apiLabel);
			repo.setRepoName(repoName);
			repo.setRuleset(rulesetService.getDefaultRuleset());
			repo.setScanType(type);
		}
		repo.setLastReviewedDate(System.currentTimeMillis());
		repo.setEnabled(true);
		return repoRepo.save(repo);
	}

	/** The most repositories one bulk change may touch. */
	public static final int MAX_BULK = 500;

	/**
	 * Gives many repositories the same ruleset, with the same rules as one at a time.
	 *
	 * @param rulesetId the ruleset, -1 for none
	 * @param repoIds   the repositories, at most {@value #MAX_BULK}
	 * @return how many repositories changed
	 * @throws RulesetNotFoundException if the ruleset does not exist
	 * @throws RulesetException         if it is a supporting ruleset
	 */
	@Transactional
	public int setRulesetForRepos(long rulesetId, List<Long> repoIds)
			throws RulesetNotFoundException, RulesetException {
		checkBulkSize(repoIds);
		rulesetService.lockConfiguration();
		RulesetEntity ruleset = primaryRuleset(rulesetId);
		List<RepositoryEntity> repos = repoRepo.findAllById(repoIds);
		repos.forEach(repo -> repo.setRuleset(ruleset));
		repoRepo.saveAll(repos);
		return repos.size();
	}

	/**
	 * Edits many repositories at once, as the inventory's Edit dialog does for a selection: each
	 * null argument leaves that field as it is on every repository.
	 *
	 * @param repoIds   the repositories, at most {@value #MAX_BULK}
	 * @param rulesetId the ruleset, -1 for none, null to keep each one's
	 * @return how many repositories were edited
	 * @throws IllegalArgumentException if every field is left as it is, or a value is not valid
	 */
	@Transactional
	public int editMany(List<Long> repoIds, Long rulesetId, String team, String owner,
			List<String> labels, Integer criticality)
			throws RulesetNotFoundException, RulesetException {
		if (rulesetId == null && team == null && owner == null && labels == null
				&& criticality == null) {
			throw new IllegalArgumentException("Nothing to change: every field was left as is");
		}
		int edited = updateProfiles(repoIds, team, owner, labels, criticality);
		if (rulesetId != null) {
			setRulesetForRepos(rulesetId, repoIds);
		}
		return edited;
	}

	/**
	 * Sets who owns many repositories and how they are grouped. A null argument leaves that
	 * field as it is on every repository; a blank team or owner clears it.
	 *
	 * @param repoIds     the repositories, at most {@value #MAX_BULK}
	 * @param team        the owning team
	 * @param owner       the owning person
	 * @param labels      the labels, replacing the current ones
	 * @param criticality 1 (critical) to 4 (low)
	 * @return how many repositories changed
	 * @throws IllegalArgumentException if a value is not valid
	 */
	@Transactional
	public int updateProfiles(List<Long> repoIds, String team, String owner,
			List<String> labels, Integer criticality) {
		checkBulkSize(repoIds);
		String cleanTeam = team == null ? null : checkLength(team.trim(), 128, "Team");
		String cleanOwner = owner == null ? null : checkLength(owner.trim(), 255, "Owner");
		if (labels != null) {
			RepoLabels.format(labels);
		}
		if (criticality != null) {
			RepoCriticality.of(criticality);
		}
		List<RepositoryEntity> repos = repoRepo.findAllById(repoIds);
		for (RepositoryEntity repo : repos) {
			if (cleanTeam != null) {
				repo.setTeam(cleanTeam.isEmpty() ? null : cleanTeam);
			}
			if (cleanOwner != null) {
				repo.setOwnerName(cleanOwner.isEmpty() ? null : cleanOwner);
			}
			if (labels != null) {
				repo.setLabels(labels);
			}
			if (criticality != null) {
				repo.setCriticality(criticality);
			}
		}
		repoRepo.saveAll(repos);
		return repos.size();
	}

	private static void checkBulkSize(List<Long> repoIds) {
		if (repoIds == null || repoIds.isEmpty()) {
			throw new IllegalArgumentException("Choose at least one repository");
		}
		if (repoIds.size() > MAX_BULK) {
			throw new IllegalArgumentException("Choose at most " + MAX_BULK + " repositories");
		}
	}

	private static String checkLength(String value, int max, String field) {
		if (value.length() > max) {
			throw new IllegalArgumentException(field + " is too long");
		}
		return value;
	}

	/**
	 * Mark the repository as disabled
	 * 
	 * @param repo the repository to disable
	 * @return the repository that has been disabled
	 */
	public RepositoryEntity disableRepository(RepositoryEntity repo) {
		repo.setEnabled(false);
		return repoRepo.saveAndFlush(repo);
	}

}

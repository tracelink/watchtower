package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;

/**
 * Handles logic around SCM repositories and their rulesets
 *
 * @author csmith, mcool
 */
@Service
public class RepositoryService {

	private RepositoryRepository repoRepo;

	private RulesetService rulesetService;

	public RepositoryService(@Autowired RepositoryRepository repoRepo,
			@Autowired RulesetService rulesetService) {
		this.repoRepo = repoRepo;
		this.rulesetService = rulesetService;
	}

	/**
	 * get all repos for all Api Labels using the given scan type
	 *
	 * @param type the scan type to get repos for
	 * @return a Map of each Api Label to a list of their known repos
	 */
	public Map<String, List<RepositoryEntity>> getAllRepos(ScanType type) {
		Map<String, List<RepositoryEntity>> allRepos =
				repoRepo.findByScanType(type).stream().collect(Collectors.groupingBy(
						RepositoryEntity::getApiLabel, TreeMap::new, Collectors.toList()));
		return allRepos;
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
	public void setRulesetForRepo(long rulesetId, String apiLabel, String repoName)
			throws RulesetNotFoundException,
			RulesetException, ApiIntegrationException {
		RulesetEntity ruleset = rulesetId == -1L ? null : rulesetService.getRuleset(rulesetId);
		// Check that this is a primary ruleset
		if (ruleset != null && ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING)) {
			throw new RulesetException(
					"Cannot assign a supporting ruleset to a repository. Please select a primary ruleset.");
		}
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, repoName);
		if (repo == null) {
			throw new ApiIntegrationException("Unknown API label");
		}
		repo.setRuleset(ruleset);
		repoRepo.saveAndFlush(repo);
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
	public RepositoryEntity upsertRepo(ScanType type, String apiLabel, String repoName) {
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

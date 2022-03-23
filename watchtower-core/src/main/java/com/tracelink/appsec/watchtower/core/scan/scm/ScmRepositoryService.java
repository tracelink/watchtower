package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.Comparator;
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
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;

/**
 * Handles logic around SCM repositories and their rulesets
 *
 * @author csmith, mcool
 */
@Service
public class ScmRepositoryService {

	private ScmRepositoryRepository repoRepo;

	private RulesetService rulesetService;

	public ScmRepositoryService(@Autowired ScmRepositoryRepository repoRepo,
			@Autowired RulesetService rulesetService) {
		this.repoRepo = repoRepo;
		this.rulesetService = rulesetService;
	}

	/**
	 * get all repos for all Api Labels
	 *
	 * @return a Map of each Api Label to a list of their known repos
	 */
	public Map<String, List<ScmRepositoryEntity>> getAllRepos() {
		Map<String, List<ScmRepositoryEntity>> allRepos =
				repoRepo.findAll().stream().collect(Collectors.groupingBy(
						ScmRepositoryEntity::getApiLabel, TreeMap::new, Collectors.toList()));
		allRepos.values()
				.forEach(list -> list.sort(Comparator.comparing(ScmRepositoryEntity::getRepoName)));
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
		ScmRepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, repoName);
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
	 * @param apiLabel the api label to add this repo name to
	 * @param repoName the new repository name
	 * @return the upserted Respository information
	 */
	public ScmRepositoryEntity upsertRepo(String apiLabel, String repoName) {
		ScmRepositoryEntity repo = repoRepo.findByApiLabelAndRepoName(apiLabel, repoName);
		if (repo == null) {
			repo = new ScmRepositoryEntity();
			repo.setApiLabel(apiLabel);
			repo.setRepoName(repoName);
			repo.setRuleset(rulesetService.getDefaultRuleset());
		}
		repo.setLastReviewedDate(System.currentTimeMillis());
		repo.setEnabled(true);
		return repoRepo.save(repo);
	}

	public ScmRepositoryEntity disableRepo(ScmRepositoryEntity repo) {
		repo.setEnabled(false);
		return repoRepo.saveAndFlush(repo);
	}

}

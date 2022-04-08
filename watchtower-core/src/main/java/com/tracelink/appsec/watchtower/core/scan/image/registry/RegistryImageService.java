package com.tracelink.appsec.watchtower.core.scan.image.registry;

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
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;

@Service
public class RegistryImageService {
	private RegistryImageRepository regRepo;

	private RulesetService rulesetService;

	public RegistryImageService(
			@Autowired RegistryImageRepository regRepo,
			@Autowired RulesetService rulesetService) {
		this.regRepo = regRepo;
		this.rulesetService = rulesetService;
	}

	public RegistryImageEntity upsertRegistryImage(String apiLabel, String imageName) {
		RegistryImageEntity reg = regRepo.findByApiLabelAndImageName(apiLabel, imageName);
		if (reg == null) {
			reg = new RegistryImageEntity();
			reg.setApiLabel(apiLabel);
			reg.setRegistryImageName(imageName);
			reg.setRuleset(rulesetService.getDefaultRuleset());
		}
		reg.setLastReviewedDate(System.currentTimeMillis());
		reg.setEnabled(true);
		return regRepo.save(reg);
	}

	/**
	 * Tie a ruleset entity to an image under an Api Label
	 *
	 * @param rulesetId ID of the ruleset to use
	 * @param apiLabel  the Api that can talk to the repo
	 * @param imageName which image to configure
	 * @throws RulesetNotFoundException if the ruleset doesn't exist or the apiLabel is unknown
	 * @throws RulesetException         if a non-primary ruleset is being assigned to an image
	 * @throws ApiIntegrationException  if the apiLabel is unknown
	 */
	public void setRulesetForImage(long rulesetId, String apiLabel, String imageName)
			throws RulesetNotFoundException,
			RulesetException, ApiIntegrationException {
		RulesetEntity ruleset = rulesetId == -1L ? null : rulesetService.getRuleset(rulesetId);
		// Check that this is a primary ruleset
		if (ruleset != null && ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING)) {
			throw new RulesetException(
					"Cannot assign a supporting ruleset to a repository. Please select a primary ruleset.");
		}
		RegistryImageEntity reg = regRepo.findByApiLabelAndImageName(apiLabel, imageName);
		if (reg == null) {
			throw new ApiIntegrationException("Unknown API label");
		}
		reg.setRuleset(ruleset);
		regRepo.saveAndFlush(reg);
	}

	/**
	 * get all images in registries for all Api Labels
	 *
	 * @return a Map of each Api Label to a list of their known registry images
	 */
	public Map<String, List<RegistryImageEntity>> getAllRegistryImages() {
		Map<String, List<RegistryImageEntity>> allRepos =
				regRepo.findAll().stream().collect(Collectors.groupingBy(
						RegistryImageEntity::getApiLabel, TreeMap::new, Collectors.toList()));
		allRepos.values()
				.forEach(list -> list
						.sort(Comparator.comparing(RegistryImageEntity::getRegistryImageName)));
		return allRepos;
	}

}

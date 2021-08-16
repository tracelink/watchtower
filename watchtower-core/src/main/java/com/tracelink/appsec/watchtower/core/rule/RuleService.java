package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.ruleset.ImportOption;

/**
 * Handles logic to retrieve and delete rules, regardless of rule type.
 *
 * @author mcool
 */
@Service
public class RuleService {
	private static final Logger LOG = LoggerFactory.getLogger(RuleService.class);

	private RuleRepository ruleRepository;

	/**
	 * Creates an instance of this service with a {@link RuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public RuleService(@Autowired RuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets a list of all rules. Each rule is translated into a {@link RuleDto} for convenience.
	 *
	 * @return list of DTOs for all rules in the database
	 */
	public List<RuleDto> getRules() {
		return Collections.unmodifiableList(
				ruleRepository.findAll().stream().map(RuleEntity::toDto).sorted()
						.collect(Collectors.toList()));
	}

	/**
	 * Gets the rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return rule with the given ID
	 * @throws RuleNotFoundException if no rule with the given ID exists
	 */
	public RuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<RuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such rule exists.");
		}
		return rule.get();
	}

	/**
	 * Gets the rule with the given name.
	 *
	 * @param name name of the rule to retrieve
	 * @return rule with the given name, or null if not found
	 */
	public RuleEntity getRule(String name) {
		return ruleRepository.findByName(name);
	}

	public List<RuleDto> getRulesForModule(String module) {
		List<RuleEntity> rules = ruleRepository.findAll();

		return rules.stream().map(RuleEntity::toDto)
				.filter(r -> r.getModule().equalsIgnoreCase(module)).sorted()
				.collect(Collectors.toList());
	}

	/**
	 * Deletes the rule with the given ID.
	 *
	 * @param id ID of the rule to delete
	 * @throws RuleNotFoundException if no rule with the given ID exists
	 */
	public void deleteRule(long id) throws RuleNotFoundException {
		RuleEntity rule = getRule(id);
		ruleRepository.delete(rule);
	}

	/**
	 * Determines whether changing the name of the rule with the given ID to the given name will
	 * result in a name collision. Used to prevent multiple rules in the database from having the
	 * same name.
	 *
	 * @param id   ID of the rule to edit
	 * @param name proposed new name for the rule with the given ID
	 * @return true if a different rule in the database already has the given name, false otherwise
	 */
	public boolean createsNameCollision(long id, String name) {
		RuleEntity rule = getRule(name);
		return rule != null && rule.getId() != id;
	}


	private <T extends RuleDto> void validateRules(Set<T> ruleDtos) throws RuleException {
		ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
		Validator validator = validatorFactory.getValidator();
		// Validate fields of the rule
		StringBuilder sb = new StringBuilder();
		for (T ruleDto : ruleDtos) {
			Set<ConstraintViolation<T>> violations = validator.validate(ruleDto);
			if (!violations.isEmpty()) {
				sb.append("\nRule: " + ruleDto.getName() + " violations: ");
				sb.append(violations.stream().map(v -> v.getMessage())
						.collect(Collectors.joining(", ")));
			}
		}
		if (sb.length() > 0) {
			throw new RuleException("One or more rules are invalid." + sb.toString());
		}
	}

	/**
	 * Imports the given set of rule DTOs and stores each in the database. For each new rule entity,
	 * assign the given user as the author of the rule.
	 *
	 * @param dtos             set of rule DTOs to import
	 * @param backupAuthorName name to assign as author of the rules, if it is not part of the given
	 *                         rule
	 * @param customOption     the option used during custom rule imports
	 * @param providedOption   the option used during provided rule imports
	 * @return list of database entity rules that have been imported
	 * @throws RuleException if there is a rule that already exists with the same name
	 */
	public List<RuleEntity> importRules(Set<RuleDto> dtos, String backupAuthorName,
			ImportOption customOption, ImportOption providedOption)
			throws RuleException {
		// ensure authors are set correctly
		dtos.stream()
				.filter(r -> (RuleDesignation.CUSTOM.equals(r.getRuleDesignation())
						&& StringUtils.isBlank(r.getAuthor())))
				.forEach(r -> ((CustomRuleDto) r).setAuthor(backupAuthorName));

		validateRules(dtos);

		Set<RuleEntity> rules = new HashSet<>();
		for (RuleDto rule : dtos) {
			LOG.debug("Importing Rule {}", rule.getName());
			RuleEntity found = ruleRepository.findByName(rule.getName());
			if (found != null) {
				if (customOption.equals(ImportOption.SKIP)) {
					// don't update, just skip
					LOG.debug("Skipping update of rule {}", rule.getName());
				} else if (rule.getRuleDesignation().equals(RuleDesignation.PROVIDED)) {
					// On update, only update the priority
					if (providedOption.equals(ImportOption.SKIP)) {
						LOG.debug("Skipping update of provided rule {}", rule.getName());
					} else if (providedOption.equals(ImportOption.UPDATE)) {
						found.setPriority(rule.getPriority());
						rules.add(found);
					} else if (providedOption.equals(ImportOption.OVERRIDE)) {
						// update the old rule with the new info
						RuleEntity ruleEntity = rule.toEntity();
						ruleEntity.setId(found.getId());
						rules.add(ruleEntity);
					}
				} else {
					// update the old rule with the new info
					RuleEntity ruleEntity = rule.toEntity();
					ruleEntity.setId(found.getId());
					rules.add(ruleEntity);
				}
			} else {
				// new rule
				RuleEntity ruleEntity = rule.toEntity();
				rules.add(ruleEntity);
			}
		}
		List<RuleEntity> saveRules = ruleRepository.saveAll(rules);
		ruleRepository.flush();
		return saveRules;
	}

}

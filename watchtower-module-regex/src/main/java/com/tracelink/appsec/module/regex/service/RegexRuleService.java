package com.tracelink.appsec.module.regex.service;

import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.module.regex.model.RegexRuleEntity;
import com.tracelink.appsec.module.regex.repository.RegexRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Handles logic to retrieve and edit Regex rules.
 *
 * @author mcool
 */
@Service
public class RegexRuleService {

	private RegexRuleRepository ruleRepository;

	/**
	 * Creates and instance of this service with a {@link RegexRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public RegexRuleService(@Autowired RegexRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the Regex rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return Regex rule with the given ID
	 * @throws RuleNotFoundException if no Regex rule with the given id exists
	 */
	public RegexRuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<RegexRuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such regex rule exists.");
		}
		return rule.get();
	}

	/**
	 * Edits the Regex rule with the same ID as the given {@link RegexRuleDto}. Updates select
	 * fields of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the Regex rule
	 * @throws RuleNotFoundException if no Regex rule exists with the same ID as the given DTO
	 */
	public void editRule(RegexRuleDto dto)
			throws RuleNotFoundException {
		RegexRuleEntity rule = getRule(dto.getId());
		// Set inherited fields
		rule.setName(dto.getName());
		rule.setMessage(dto.getMessage());
		rule.setExternalUrl(dto.getExternalUrl());
		rule.setPriority(dto.getPriority());
		// Set Regex-specific fields
		rule.setFileExtension(dto.getFileExtension());
		rule.setRegexPattern(dto.getRegexPattern());
		ruleRepository.saveAndFlush(rule);
	}

	/**
	 * Save the supplied DTO as a Regex Rule Entity
	 *
	 * @param dto the rule data to save
	 * @throws RuleDesignerException if the rule name already exists
	 */
	public void saveNewRule(RegexRuleDto dto) throws RuleDesignerException {
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException(
					"Rule with the name " + dto.getName() + " already exists");
		}
		RegexRuleEntity entity = dto.toEntity();
		entity.setAuthor(dto.getAuthor());
		ruleRepository.saveAndFlush(entity);
	}

}

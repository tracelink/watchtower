package com.tracelink.appsec.module.pmd.service;

import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyEntity;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleEntity;
import com.tracelink.appsec.module.pmd.repository.PMDRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Handles logic to retrieve and edit PMD rules.
 *
 * @author mcool
 */
@Service
public class PMDRuleService {

	private final List<String> supportedLanguages =
			Arrays.asList("Java", "Ecmascript", "Scala", "XML");

	private final PMDRuleRepository ruleRepository;

	/**
	 * Creates and instance of this service with a {@link PMDRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public PMDRuleService(@Autowired PMDRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the PMD rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return PMD rule with the given ID
	 * @throws RuleNotFoundException if no PMD rule with the given id exists
	 */
	public PMDRuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<PMDRuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such PMD rule exists.");
		}
		return rule.get();
	}

	/**
	 * Edits the PMD rule with the same ID as the given {@link PMDRuleDto}. Updates select fields of
	 * the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the PMD rule
	 * @throws RuleNotFoundException if no PMD rule exists with the same ID as the given DTO
	 */
	public void editRule(PMDRuleDto dto) throws RuleNotFoundException {
		PMDRuleEntity rule = getRule(dto.getId());
		// Set inherited fields
		rule.setName(dto.getName());
		rule.setMessage(dto.getMessage());
		rule.setExternalUrl(dto.getExternalUrl());
		rule.setPriority(dto.getPriority());
		// Set PMD-specific fields
		rule.setDescription(dto.getDescription());
		// Set PMD properties
		for (PMDPropertyEntity propertyEntity : rule.getProperties()) {
			for (PMDPropertyDto propertyDto : dto.getProperties()) {
				if (propertyEntity.getId() == propertyDto.getId()) {
					propertyEntity.setName(propertyDto.getName());
					propertyEntity.setValue(propertyDto.getValue());
				}
			}
		}
		ruleRepository.saveAndFlush(rule);
	}

	/**
	 * Save the supplied DTO as a PMD Rule Entity
	 *
	 * @param dto the rule data to save
	 * @throws RuleDesignerException if the rule name already exists
	 */
	public void saveNewRule(PMDRuleDto dto) throws RuleDesignerException {
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException(
					"Rule with the name " + dto.getName() + " already exists");
		}
		if (supportedLanguages.contains(dto.getParserLanguage())) {
			dto.setParserLanguage(dto.getParserLanguage().toLowerCase());
		} else {
			throw new RuleDesignerException(
					"Please select a supported language: " + String
							.join(", ", supportedLanguages));
		}
		PMDRuleEntity entity = dto.toEntity();
		entity.setAuthor(dto.getAuthor());
		ruleRepository.saveAndFlush(entity);
	}

}

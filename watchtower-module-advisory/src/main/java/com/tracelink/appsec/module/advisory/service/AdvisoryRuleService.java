package com.tracelink.appsec.module.advisory.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.module.advisory.model.AdvisoryRuleEntity;
import com.tracelink.appsec.module.advisory.repository.AdvisoryRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;

/**
 * Handles logic to retrieve and edit Advisory rules.
 *
 * @author csmith
 */
@Service
public class AdvisoryRuleService {

	private final AdvisoryRuleRepository ruleRepository;

	/**
	 * Creates an instance of this service with a {@link AdvisoryRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public AdvisoryRuleService(@Autowired AdvisoryRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the Advisory rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return Advisory rule with the given ID
	 * @throws RuleNotFoundException if no Advisory rule with the given id exists
	 */
	public AdvisoryRuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<AdvisoryRuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such advisory rule exists.");
		}
		return rule.get();
	}

	/**
	 * Edits the Advisory rule with the same ID as the given {@link AdvisoryRuleDto}. Updates select
	 * fields of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the Advisory rule
	 * @throws RuleNotFoundException if no Advisory rule exists with the same ID as the given DTO
	 */
	public void editRule(AdvisoryRuleDto dto)
			throws RuleNotFoundException {
		AdvisoryRuleEntity rule = getRule(dto.getId());
		// Set inherited fields
		rule.setName(dto.getName());
		rule.setMessage(dto.getMessage());
		rule.setExternalUrl(dto.getExternalUrl());
		rule.setPriority(dto.getPriority());
		rule.setAuthor(dto.getAuthor());
		ruleRepository.saveAndFlush(rule);
	}

	/**
	 * Save the supplied DTO as a Advisory Rule Entity
	 *
	 * @param dto the rule data to save
	 * @throws RuleDesignerException if the rule name already exists
	 */
	public AdvisoryRuleEntity saveNewRule(AdvisoryRuleDto dto) throws RuleDesignerException {
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException(
					"Rule with the name " + dto.getName() + " already exists");
		}
		AdvisoryRuleEntity entity = dto.toEntity();
		entity.setAuthor(dto.getAuthor());
		return ruleRepository.saveAndFlush(entity);
	}

}

package com.tracelink.appsec.module.json.service;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.model.JsonRuleEntity;
import com.tracelink.appsec.module.json.repository.JsonRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Handles logic to retrieve and edit Json rules.
 *
 * @author csmith
 */
@Service
public class JsonRuleService {

	private final JsonRuleRepository ruleRepository;

	/**
	 * Creates and instance of this service with a {@link JsonRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public JsonRuleService(@Autowired JsonRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the Json rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return Json rule with the given ID
	 * @throws RuleNotFoundException if no Json rule with the given id exists
	 */
	public JsonRuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<JsonRuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such json rule exists.");
		}
		return rule.get();
	}

	/**
	 * Edits the Json rule with the same ID as the given {@link JsonRuleDto}. Updates select fields
	 * of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the Json rule
	 * @throws RuleNotFoundException if no Json rule exists with the same ID as the given DTO
	 */
	public void editRule(JsonRuleDto dto)
			throws RuleNotFoundException {
		JsonRuleEntity rule = getRule(dto.getId());
		// Set inherited fields
		rule.setName(dto.getName());
		rule.setMessage(dto.getMessage());
		rule.setExternalUrl(dto.getExternalUrl());
		rule.setPriority(dto.getPriority());
		// Set Json-specific fields
		rule.setFileExtension(dto.getFileExtension());
		rule.setQuery(dto.getQuery());
		ruleRepository.saveAndFlush(rule);
	}

	/**
	 * Save the supplied DTO as a Json Rule Entity
	 *
	 * @param dto the rule data to save
	 * @throws RuleDesignerException if the rule name already exists
	 */
	public void saveNewRule(JsonRuleDto dto) throws RuleDesignerException {
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException(
					"Rule with the name " + dto.getName() + " already exists");
		}
		JsonRuleEntity entity = dto.toEntity();
		entity.setAuthor(dto.getAuthor());
		ruleRepository.saveAndFlush(entity);
	}

}

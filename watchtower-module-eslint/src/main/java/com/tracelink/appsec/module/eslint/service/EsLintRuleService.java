package com.tracelink.appsec.module.eslint.service;

import javax.validation.Validator;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageEntity;
import com.tracelink.appsec.module.eslint.model.EsLintRuleEntity;
import com.tracelink.appsec.module.eslint.repository.EsLintRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Handles logic to retrieve and edit ESLint rules.
 *
 * @author mcool
 */
@Service
public class EsLintRuleService {

	private final EsLintRuleRepository ruleRepository;
	private final LinterEngine engine;

	public EsLintRuleService(@Autowired EsLintRuleRepository ruleRepository,
			@Autowired LinterEngine engine) {
		this.ruleRepository = ruleRepository;
		this.engine = engine;
	}

	/**
	 * Gets the ESLint rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return ESLint rule with the given ID
	 */
	public EsLintRuleEntity getRule(long id) {
		return ruleRepository.findById(id).orElse(null);
	}

	/**
	 * Saves the given ESLint rule DTO to the database and performs additional validation. Assumes
	 * that the DTO has already been partially validated using a {@link Validator}.
	 *
	 * @param dto the DTO representing the rule to be saved
	 * @throws RuleDesignerException if the rule is invalid or cannot be saved
	 */
	public void saveRule(EsLintCustomRuleDto dto) throws RuleDesignerException {
		// Make sure there are no name collisions
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException("An ESLint rule with the given name already exists");
		}
		// Make sure the rule is not a core rule
		if (engine.getCoreRules().containsKey(dto.getName())) {
			throw new RuleDesignerException("\"" + dto.getName()
					+ "\" is a core rule. Please provide a different name");
		}
		// Make sure the create function is not empty
		if (StringUtils.isBlank(dto.getCreateFunction())) {
			throw new RuleDesignerException(
					"Please provide a create function that is not empty");
		}
		// Save rule
		ruleRepository.saveAndFlush(dto.toEntity());
	}

	/**
	 * Edits the ESLint rule with the same ID as the given {@link EsLintCustomRuleDto}. Updates
	 * select fields of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the ESLint rule
	 * @throws RuleNotFoundException if no ESLint rule exists with the same ID as the given DTO
	 * @throws RuleEditorException   if a custom rule is being edited and does not have a create
	 *                               function
	 */
	public void editRule(RuleDto dto)
			throws RuleNotFoundException, RuleEditorException {
		EsLintRuleEntity rule = getRule(dto.getId());
		if (rule == null) {
			throw new RuleNotFoundException("No such ESLint rule exists.");
		}
		if (rule.isCore()) {
			// Only allowed to edit the priority field
			rule.setPriority(dto.getPriority());
		} else {
			EsLintCustomRuleDto custom = (EsLintCustomRuleDto) dto;
			// Make sure the create function is not empty
			if (StringUtils.isBlank(custom.getCreateFunction())) {
				throw new RuleEditorException("Please provide a nonempty create function.");
			}
			// Set inherited fields
			rule.setName(custom.getName());
			rule.setMessage(custom.getMessage());
			rule.setExternalUrl(custom.getExternalUrl());
			rule.setPriority(custom.getPriority());
			// Set ESLint-specific fields
			for (EsLintMessageEntity propertyEntity : rule.getMessages()) {
				for (EsLintMessageDto propertyDto : custom.getMessages()) {
					if (propertyEntity.getId() == propertyDto.getId()) {
						propertyEntity.setKey(propertyDto.getKey());
						propertyEntity.setValue(propertyDto.getValue());
					}
				}
			}
			rule.setCreateFunction(custom.getCreateFunction());
		}
		ruleRepository.saveAndFlush(rule);
	}
}

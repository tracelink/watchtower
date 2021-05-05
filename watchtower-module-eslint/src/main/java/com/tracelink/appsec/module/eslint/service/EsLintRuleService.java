package com.tracelink.appsec.module.eslint.service;

import java.util.Map;
import java.util.stream.Collectors;

import javax.validation.Validator;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageEntity;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleEntity;
import com.tracelink.appsec.module.eslint.repository.EsLintRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;

/**
 * Handles logic to retrieve and edit ESLint rules.
 *
 * @author mcool
 */
@Service
public class EsLintRuleService {

	private final EsLintRuleRepository ruleRepository;

	public EsLintRuleService(@Autowired EsLintRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
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
	public void saveRule(EsLintRuleDto dto) throws RuleDesignerException {
		// Make sure there are no name collisions
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException("An ESLint rule with the given name already exists");
		}
		// Set fields common to both core and custom rules
		EsLintRuleEntity rule = new EsLintRuleEntity();
		rule.setAuthor(dto.getAuthor());
		rule.setCore(dto.isCore());
		rule.setName(dto.getName());
		rule.setPriority(dto.getPriority());

		Map<String, Map<String, String>> coreRules = LinterEngine.getInstance().getCoreRules();
		// Set fields specific to core or custom rule
		if (dto.isCore()) {
			if (coreRules.containsKey(dto.getName())) {
				Map<String, String> coreRuleValues = coreRules.get(dto.getName());
				rule.setMessage(coreRuleValues.get("description"));
				rule.setExternalUrl(coreRuleValues.get("url"));
			} else {
				throw new RuleDesignerException("\"" + dto.getName()
						+ "\" is not a core rule. Please choose from the provided list");
			}
		} else {
			// Make sure the rule is not a core rule
			if (coreRules.containsKey(dto.getName())) {
				throw new RuleDesignerException("\"" + dto.getName()
						+ "\" is a core rule. Please provide a different name");
			}
			// Make sure the create function is not empty
			if (StringUtils.isBlank(dto.getCreateFunction())) {
				throw new RuleDesignerException(
						"Please provide a create function that is not empty");
			}
			rule.setMessage(dto.getMessage());
			rule.setExternalUrl(dto.getExternalUrl());
			rule.setMessages(dto.getMessages().stream().map(EsLintMessageDto::toEntity)
					.collect(Collectors.toList()));
			rule.setCreateFunction(dto.getCreateFunction());
		}
		// Save rule
		ruleRepository.saveAndFlush(rule);
	}

	/**
	 * Edits the ESLint rule with the same ID as the given {@link EsLintRuleDto}. Updates select
	 * fields of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the ESLint rule
	 * @throws RuleNotFoundException if no ESLint rule exists with the same ID as the given DTO
	 * @throws RuleEditorException   if a custom rule is being edited and does not have a create
	 *                               function
	 */
	public void editRule(EsLintRuleDto dto) throws RuleNotFoundException, RuleEditorException {
		EsLintRuleEntity rule = getRule(dto.getId());
		if (rule == null) {
			throw new RuleNotFoundException("No such ESLint rule exists.");
		}
		if (rule.isCore()) {
			// Only allowed to edit the priority field
			rule.setPriority(dto.getPriority());
		} else {
			// Make sure the create function is not empty
			if (StringUtils.isBlank(dto.getCreateFunction())) {
				throw new RuleEditorException("Please provide a nonempty create function.");
			}
			// Set inherited fields
			rule.setName(dto.getName());
			rule.setMessage(dto.getMessage());
			rule.setExternalUrl(dto.getExternalUrl());
			rule.setPriority(dto.getPriority());
			// Set ESLint-specific fields
			for (EsLintMessageEntity propertyEntity : rule.getMessages()) {
				for (EsLintMessageDto propertyDto : dto.getMessages()) {
					if (propertyEntity.getId() == propertyDto.getId()) {
						propertyEntity.setKey(propertyDto.getKey());
						propertyEntity.setValue(propertyDto.getValue());
					}
				}
			}
			rule.setCreateFunction(dto.getCreateFunction());
		}
		ruleRepository.saveAndFlush(rule);
	}
}

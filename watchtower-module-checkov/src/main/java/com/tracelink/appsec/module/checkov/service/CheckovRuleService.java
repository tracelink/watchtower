package com.tracelink.appsec.module.checkov.service;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleEntity;
import com.tracelink.appsec.module.checkov.repository.CheckovRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;

/**
 * Service definition for managing Checkov Rules
 * 
 * @author csmith
 *
 */
@Service
public class CheckovRuleService {

	private final CheckovRuleRepository ruleRepository;

	public CheckovRuleService(@Autowired CheckovRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the Checkov rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return Checkov rule with the given ID, or null
	 */
	public CheckovRuleEntity getRule(long id) {
		return ruleRepository.findById(id).orElse(null);
	}

	/**
	 * Edit the saved rule given the input rule
	 * 
	 * @param dto the {@linkplain CheckovRuleDto} with changes to save
	 * @throws RuleNotFoundException if there is no corresponding rule already saved
	 * @throws RuleEditorException   if the rule is attempting to edit something illegal (e.g. a
	 *                               core rule cannot edit a custom rule)
	 */
	public void editRule(@Valid CheckovRuleDto dto)
			throws RuleNotFoundException, RuleEditorException {
		CheckovRuleEntity rule = getRule(dto.getId());
		if (rule == null) {
			throw new RuleNotFoundException("No such Checkov rule exists.");
		}
		if (rule.isCoreRule()) {
			// Only allowed to edit the priority field
			rule.setPriority(dto.getPriority());
		} else {
			throw new RuleEditorException("Unknown Rule. Only supports Core Rules");
		}
		ruleRepository.saveAndFlush(rule);
	}

}

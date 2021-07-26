package com.tracelink.appsec.module.checkov.service;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleEntity;
import com.tracelink.appsec.module.checkov.repository.CheckovRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;

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
	 * @param dto the {@linkplain CheckovProvidedRuleDto} with changes to save
	 * @throws RuleNotFoundException if there is no corresponding rule already saved
	 */
	public void editProvidedRule(@Valid CheckovProvidedRuleDto dto)
			throws RuleNotFoundException {
		CheckovRuleEntity rule = getRule(dto.getId());
		if (rule == null) {
			throw new RuleNotFoundException("No such Checkov Provided rule exists.");
		}
		rule.setPriority(dto.getPriority());
		ruleRepository.saveAndFlush(rule);
	}

}

package com.tracelink.appsec.module.regex.service;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.module.regex.model.RegexRuleEntity;
import com.tracelink.appsec.module.regex.repository.RegexRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Handles logic to retrieve and edit Regex rules.
 *
 * @author mcool
 */
@Service
public class RegexRuleService {

	private RegexRuleRepository ruleRepository;
	private static final List<String> providedRulesets =
			Arrays.asList("/rules/trufflehog-regexes.json");
	private final JsonMapper jsonMapper;

	/**
	 * Creates and instance of this service with a {@link RegexRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public RegexRuleService(@Autowired RegexRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
		PolymorphicTypeValidator v =
				BasicPolymorphicTypeValidator.builder()
						.allowIfBaseType(RuleDto.class)
						.allowIfBaseType(Set.class)
						.allowIfBaseType(RulesetDto.class)
						.build();

		jsonMapper =
				JsonMapper.builder().polymorphicTypeValidator(v).activateDefaultTyping(v).build();
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

	public List<RulesetDto> getProvidedRulesets() {
		return providedRulesets.stream().map(this::getRuleset).collect(Collectors.toList());
	}

	private RulesetDto getRuleset(String location) {
		try (InputStream is = getClass().getResourceAsStream(location)) {
			RulesetDto dto = jsonMapper.readValue(is, RulesetDto.class);
			dto.getRules().stream().map(r -> (RegexRuleDto) r).forEach(r -> {
				r.setPriority(RulePriority.LOW);
				r.setAuthor("system");
			});
			dto.setDesignation(RulesetDesignation.PROVIDED);
			dto.setBlockingLevel(RulePriority.LOW);
			return dto;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}

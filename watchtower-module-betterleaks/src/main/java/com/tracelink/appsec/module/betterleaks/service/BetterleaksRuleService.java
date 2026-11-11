package com.tracelink.appsec.module.betterleaks.service;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleEntity;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity;
import com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleRepository;
import com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleVersionRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Manages Betterleaks rules: priority edits to provided rules, and the full life cycle of custom
 * rules. A custom rule is saved only after the real binary proves it matches its positive sample
 * and not its negative one, and every save is kept as a version.
 *
 * @author Watchtower
 */
@Service
public class BetterleaksRuleService {

	private void invalidateRuleCache() { coreRuleService.invalidateRuleCache(); }

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksRuleService.class);

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private final BetterleaksRuleRepository ruleRepository;

	private final BetterleaksRuleVersionRepository versionRepository;

	private final RuleService coreRuleService;

	private final BetterleaksRuleTester tester;

	@Autowired
	public BetterleaksRuleService(BetterleaksRuleRepository ruleRepository,
			BetterleaksRuleVersionRepository versionRepository, RuleService coreRuleService,
			BetterleaksRuleTester tester) {
		this.ruleRepository = ruleRepository;
		this.versionRepository = versionRepository;
		this.coreRuleService = coreRuleService;
		this.tester = tester;
	}

	/**
	 * Changes a provided rule's priority - the only part of a provided rule that is editable. Every
	 * other submitted field is ignored, so a tampered form cannot rename or re-target a rule.
	 *
	 * @param dto the submitted rule; only its id and priority are used
	 * @throws RuleNotFoundException    if no such rule exists
	 * @throws IllegalArgumentException if no priority was submitted
	 */
	public void editProvidedRule(BetterleaksProvidedRuleDto dto) throws RuleNotFoundException {
		if (dto.getPriority() == null) {
			throw new IllegalArgumentException("A priority is required.");
		}
		BetterleaksRuleEntity rule = dto.getId() == null ? null
				: ruleRepository.findById(dto.getId()).orElse(null);
		if (rule == null) {
			throw new RuleNotFoundException("No such Betterleaks rule exists.");
		}
		rule.setPriority(dto.getPriority());
		ruleRepository.saveAndFlush(rule);
		invalidateRuleCache();
	}

	/**
	 * Tests and saves a new custom rule as version 1.
	 *
	 * @param rule   the rule from the designer
	 * @param author who is saving it
	 * @return the saved rule
	 * @throws IllegalArgumentException with a user-facing reason if the rule is invalid, fails its
	 *                                  sample test, or its name is taken
	 */
	public BetterleaksRuleEntity saveNewCustomRule(BetterleaksCustomRuleDto rule, String author) {
		rule.setAuthor(author);
		rule.setVersion(1);
		if (coreRuleService.getRule(rule.getName()) != null) {
			throw new IllegalArgumentException("A rule named " + rule.getName()
					+ " already exists.");
		}
		requirePassingTest(rule);
		BetterleaksRuleEntity saved = ruleRepository.saveAndFlush(rule.toEntity());
		invalidateRuleCache();
		recordVersion(saved.getId(), rule, author);
		LOG.info("Custom Betterleaks rule {} created by {}", rule.getBetterleaksId(), author);
		return saved;
	}

	/**
	 * Tests and saves a new version of a custom rule. Its id, name and author never change; the
	 * detection fields, guidance, priority and samples do.
	 *
	 * @param submitted the edited rule; its id says which rule to change
	 * @param editor    who is editing it
	 * @throws IllegalArgumentException with a user-facing reason if there is no such custom rule,
	 *                                  or the edit is invalid or fails its sample test
	 */
	public void editCustomRule(BetterleaksCustomRuleDto submitted, String editor) {
		BetterleaksRuleEntity entity = submitted.getId() == null ? null
				: ruleRepository.findById(submitted.getId()).orElse(null);
		if (entity == null || entity.isProvided()) {
			throw new IllegalArgumentException("No such custom Betterleaks rule.");
		}
		BetterleaksCustomRuleDto updated = (BetterleaksCustomRuleDto) entity.toDto();
		updated.setMessage(submitted.getMessage());
		updated.setExternalUrl(submitted.getExternalUrl());
		updated.setPriority(submitted.getPriority());
		updated.setRegex(submitted.getRegex());
		updated.setKeywords(submitted.getKeywords());
		updated.setEntropy(submitted.getEntropy());
		updated.setSecretGroup(submitted.getSecretGroup());
		updated.setFilter(submitted.getFilter());
		updated.setPositiveSample(submitted.getPositiveSample());
		updated.setNegativeSample(submitted.getNegativeSample());
		updated.setVersion(updated.getVersion() + 1);
		requirePassingTest(updated);

		BetterleaksRuleEntity replacement = updated.toEntity();
		entity.setMessage(replacement.getMessage());
		entity.setExternalUrl(replacement.getExternalUrl());
		entity.setPriority(replacement.getPriority());
		entity.setRegex(replacement.getRegex());
		entity.setKeywords(replacement.getKeywords());
		entity.setEntropy(replacement.getEntropy());
		entity.setSecretGroup(replacement.getSecretGroup());
		entity.setFilter(replacement.getFilter());
		entity.setPositiveSample(replacement.getPositiveSample());
		entity.setNegativeSample(replacement.getNegativeSample());
		entity.setRuleVersion(updated.getVersion());
		ruleRepository.saveAndFlush(entity);
		invalidateRuleCache();
		recordVersion(entity.getId(), updated, editor);
		LOG.info("Custom Betterleaks rule {} edited by {} (version {})",
				updated.getBetterleaksId(), editor, updated.getVersion());
	}

	/**
	 * @param ruleId a custom rule
	 * @return its saved versions, newest first
	 */
	public List<BetterleaksRuleVersionEntity> getVersions(long ruleId) {
		return versionRepository.findByRuleId(ruleId).stream()
				.sorted(Comparator.comparingInt(BetterleaksRuleVersionEntity::getRuleVersion)
						.reversed())
				.toList();
	}

	private void requirePassingTest(BetterleaksCustomRuleDto rule) {
		List<String> problems = rule.fieldProblems();
		if (!problems.isEmpty()) {
			throw new IllegalArgumentException(String.join(" ", problems));
		}
		BetterleaksRuleTestResult result = tester.test(rule);
		if (!result.passed()) {
			throw new IllegalArgumentException(result.failureReason());
		}
	}

	private void recordVersion(long ruleId, BetterleaksCustomRuleDto rule, String author) {
		BetterleaksRuleVersionEntity version = new BetterleaksRuleVersionEntity();
		version.setRuleId(ruleId);
		version.setRuleVersion(rule.getVersion());
		version.setDefinition(definitionJson(rule));
		version.setAuthor(author);
		version.setCreatedAt(System.currentTimeMillis());
		versionRepository.save(version);
	}

	private static String definitionJson(BetterleaksCustomRuleDto rule) {
		Map<String, Object> definition = new LinkedHashMap<>();
		definition.put("id", rule.getBetterleaksId());
		definition.put("description", rule.getMessage());
		definition.put("externalUrl", rule.getExternalUrl());
		definition.put("priority", rule.getPriority() == null ? null : rule.getPriority().name());
		definition.put("regex", rule.getRegex());
		definition.put("keywords", rule.getKeywords());
		definition.put("entropy", rule.getEntropy());
		definition.put("secretGroup", rule.getSecretGroup());
		definition.put("filter", rule.getFilter());
		definition.put("positiveSample", rule.getPositiveSample());
		definition.put("negativeSample", rule.getNegativeSample());
		try {
			return MAPPER.writeValueAsString(definition);
		} catch (JsonProcessingException e) {
			throw new IllegalStateException("Could not record the rule version", e);
		}
	}
}

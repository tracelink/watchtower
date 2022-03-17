package com.tracelink.appsec.module.regex.service;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexRuleEntity;
import com.tracelink.appsec.module.regex.repository.RegexRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@ExtendWith(SpringExtension.class)
public class RegexRuleServiceTest {

	private static final String RULE_NAME = "Regex Rule";

	@MockBean
	private RegexRuleRepository ruleRepository;

	private RegexRuleService ruleService;
	private RegexRuleEntity rule;

	@BeforeEach
	public void setup() {
		ruleService = new RegexRuleService(ruleRepository);
		rule = new RegexRuleEntity();
		rule.setName(RULE_NAME);
	}

	@Test
	public void testGetRegexRule() throws Exception {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		Assertions.assertEquals(rule, ruleService.getRule(1L));
	}

	@Test
	public void testGetRegexRuleNotFound() throws Exception {
		Assertions.assertThrows(RuleNotFoundException.class, () -> {
			BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
					.thenReturn(Optional.empty());
			Assertions.assertEquals(rule, ruleService.getRule(1L));
		});
	}

	@Test
	public void testEditRule() throws Exception {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		Long dtoId = 1L;
		String dtoAuthor = "jdoe";
		String dtoName = "Regex Rule New";
		String dtoMessage = "This is a bad practice.";
		String dtoUrl = "https://example.com";
		RulePriority dtoPriority = RulePriority.MEDIUM_HIGH;
		String dtoFileExt = "";
		String dtoRegexPattern = "[abcdef]";

		RegexCustomRuleDto dto = new RegexCustomRuleDto();
		dto.setId(dtoId);
		dto.setAuthor(dtoAuthor);
		dto.setName(dtoName);
		dto.setMessage(dtoMessage);
		dto.setExternalUrl(dtoUrl);
		dto.setPriority(dtoPriority);
		dto.setFileExtension(dtoFileExt);
		dto.setRegexPattern(dtoRegexPattern);

		ruleService.editRule(dto);
		Assertions.assertEquals(0L, rule.getId());
		Assertions.assertNull(rule.getAuthor());
		Assertions.assertEquals(dtoName, rule.getName());
		Assertions.assertEquals(dtoMessage, rule.getMessage());
		Assertions.assertEquals(dtoUrl, rule.getExternalUrl());
		Assertions.assertEquals(dtoPriority, rule.getPriority());
		Assertions.assertEquals(dtoFileExt, rule.getFileExtension());
		Assertions.assertEquals(dtoRegexPattern, rule.getRegexPattern());
	}

	@Test
	public void testSaveNewRuleExists() throws Exception {
		Assertions.assertThrows(RuleDesignerException.class, () -> {
			BDDMockito.when(ruleRepository.findByName(BDDMockito.any()))
					.thenReturn(new RegexRuleEntity());
			ruleService.saveNewRule(new RegexCustomRuleDto());
		});
	}

	@Test
	public void testSaveNewRule() throws Exception {
		RegexRuleEntity entity = BDDMockito.mock(RegexRuleEntity.class);
		RegexCustomRuleDto dto = BDDMockito.mock(RegexCustomRuleDto.class);
		BDDMockito.when(dto.toEntity()).thenReturn(entity);
		ruleService.saveNewRule(dto);
		BDDMockito.verify(ruleRepository).saveAndFlush(entity);
	}
}


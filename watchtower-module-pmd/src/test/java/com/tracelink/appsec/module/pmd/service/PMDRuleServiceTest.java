package com.tracelink.appsec.module.pmd.service;

import java.util.Collections;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyEntity;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleEntity;
import com.tracelink.appsec.module.pmd.repository.PMDRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@ExtendWith(SpringExtension.class)
public class PMDRuleServiceTest {

	private static final String RULE_NAME = "PMD Rule";

	@MockBean
	private PMDRuleRepository ruleRepository;

	private PMDRuleService ruleService;
	private PMDRuleEntity rule;

	@BeforeEach
	public void setup() {
		ruleService = new PMDRuleService(ruleRepository);
		rule = new PMDRuleEntity();
		rule.setName(RULE_NAME);
	}

	@Test
	public void testGetPMDRule() throws Exception {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		Assertions.assertEquals(rule, ruleService.getRule(1L));
	}

	@Test
	public void testGetPMDRuleNotFound() throws Exception {
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
		String dtoName = "PMD Rule New";
		String dtoMessage = "This is a bad practice.";
		String dtoUrl = "https://example.com";
		RulePriority dtoPriority = RulePriority.MEDIUM_HIGH;
		String dtoLang = "javascript";
		String dtoClass = "Class.java";
		String dtoDescription = "Bad practice";
		String dtoXPath = "CDATA";

		PMDPropertyEntity propertyEntity = new PMDPropertyEntity();
		rule.setProperties(Collections.singleton(propertyEntity));

		PMDRuleDto dto = new PMDRuleDto();
		dto.setId(dtoId);
		dto.setAuthor(dtoAuthor);
		dto.setName(dtoName);
		dto.setMessage(dtoMessage);
		dto.setExternalUrl(dtoUrl);
		dto.setPriority(dtoPriority);
		dto.setParserLanguage(dtoLang);
		dto.setRuleClass(dtoClass);
		dto.setDescription(dtoDescription);
		PMDPropertyDto property = new PMDPropertyDto();
		property.setId(0L);
		property.setName("xpath");
		property.setValue(dtoXPath);
		dto.setProperties(Collections.singletonList(property));

		ruleService.editRule(dto);
		Assertions.assertEquals(0L, rule.getId());
		Assertions.assertNull(rule.getAuthor());
		Assertions.assertEquals(dtoName, rule.getName());
		Assertions.assertEquals(dtoMessage, rule.getMessage());
		Assertions.assertEquals(dtoUrl, rule.getExternalUrl());
		Assertions.assertEquals(dtoPriority, rule.getPriority());
		Assertions.assertNull(rule.getParserLanguage());
		Assertions.assertNull(rule.getRuleClass());
		Assertions.assertEquals(dtoDescription, rule.getDescription());
		PMDPropertyEntity retProp = rule.getProperties().iterator().next();
		Assertions.assertEquals("xpath", retProp.getName());
		Assertions.assertEquals(dtoXPath, retProp.getValue());
	}

	@Test
	public void testSaveNewRule() throws Exception {
		BDDMockito.when(ruleRepository.findByName(BDDMockito.anyString()))
				.thenReturn(null);
		PMDRuleDto dto = new PMDRuleDto();
		dto.setParserLanguage("Scala");
		ruleService.saveNewRule(dto);
		ArgumentCaptor<PMDRuleEntity> ruleCaptor = ArgumentCaptor.forClass(PMDRuleEntity.class);
		BDDMockito.verify(ruleRepository).saveAndFlush(ruleCaptor.capture());
		Assertions.assertEquals("scala", ruleCaptor.getValue().getParserLanguage());
	}

	@Test
	public void testSaveNewRuleNotNew() throws Exception {
		Assertions.assertThrows(RuleDesignerException.class, () -> {
			BDDMockito.when(ruleRepository.findByName(BDDMockito.any()))
					.thenReturn(new PMDRuleEntity());

			ruleService.saveNewRule(BDDMockito.mock(PMDRuleDto.class));
		});
	}

	@Test
	public void testSaveNewRuleBadLanguage() throws Exception {
		Assertions.assertThrows(RuleDesignerException.class, () -> {
			BDDMockito.when(ruleRepository.findByName(BDDMockito.anyString()))
					.thenReturn(null);
			PMDRuleDto dto = BDDMockito.mock(PMDRuleDto.class);
			BDDMockito.when(dto.getParserLanguage()).thenReturn("Foo");
			ruleService.saveNewRule(dto);
		});
	}
}

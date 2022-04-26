package com.tracelink.appsec.module.advisory.service;

import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.module.advisory.model.AdvisoryRuleEntity;
import com.tracelink.appsec.module.advisory.repository.AdvisoryRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;

@ExtendWith(SpringExtension.class)
public class AdvisoryRuleServiceTest {
	@MockBean
	private AdvisoryRuleRepository ruleRepository;

	private AdvisoryRuleService ruleService;

	@BeforeEach
	public void setup() {
		ruleService = new AdvisoryRuleService(ruleRepository);
	}

	@Test
	public void testGetRule() throws RuleNotFoundException {
		AdvisoryRuleEntity rule = new AdvisoryRuleEntity();
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		MatcherAssert.assertThat(ruleService.getRule(1L), Matchers.is(rule));
	}

	@Test
	public void testGetRuleFail() throws RuleNotFoundException {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.empty());
		Assertions.assertThrows(RuleNotFoundException.class, () -> ruleService.getRule(1L));
	}

	@Test
	public void testEditRule() throws RuleNotFoundException {
		AdvisoryRuleEntity rule = new AdvisoryRuleEntity();
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		AdvisoryRuleDto dto = new AdvisoryRuleDto();
		String name = "foo";
		dto.setName(name);
		dto.setId(1L);
		ArgumentCaptor<AdvisoryRuleEntity> capture =
				ArgumentCaptor.forClass(AdvisoryRuleEntity.class);
		ruleService.editRule(dto);
		BDDMockito.verify(ruleRepository).saveAndFlush(capture.capture());
		MatcherAssert.assertThat(capture.getValue().getName(), Matchers.is(name));
	}

	@Test
	public void testSaveNewRule() throws RuleNotFoundException, RuleDesignerException {
		BDDMockito.when(ruleRepository.findByName(BDDMockito.anyString()))
				.thenReturn(null);
		AdvisoryRuleDto dto = new AdvisoryRuleDto();
		String name = "foo";
		dto.setName(name);
		BDDMockito.when(ruleRepository.saveAndFlush(BDDMockito.any()))
				.thenAnswer((e) -> e.getArgument(0));
		AdvisoryRuleEntity entity = ruleService.saveNewRule(dto);
		MatcherAssert.assertThat(entity.getName(), Matchers.is(name));
	}

	@Test
	public void testSaveNewRuleFail() throws RuleNotFoundException, RuleDesignerException {
		BDDMockito.when(ruleRepository.findByName(BDDMockito.anyString()))
				.thenReturn(new AdvisoryRuleEntity());
		AdvisoryRuleDto dto = new AdvisoryRuleDto();
		String name = "foo";
		dto.setName(name);
		RuleDesignerException exception = Assertions.assertThrows(RuleDesignerException.class,
				() -> ruleService.saveNewRule(dto));
		MatcherAssert.assertThat(exception.getMessage(),
				Matchers.containsString(name + " already exists"));
	}
}

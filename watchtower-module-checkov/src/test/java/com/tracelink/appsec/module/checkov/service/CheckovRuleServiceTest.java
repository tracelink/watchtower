package com.tracelink.appsec.module.checkov.service;

import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleEntity;
import com.tracelink.appsec.module.checkov.repository.CheckovRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@ExtendWith(SpringExtension.class)
public class CheckovRuleServiceTest {

	@MockBean
	private CheckovRuleRepository mockRuleRepository;

	private CheckovRuleService ruleService;

	@BeforeEach
	public void setup() {
		ruleService = new CheckovRuleService(mockRuleRepository);
	}

	@Test
	public void testEditRule() throws Exception {
		CheckovRuleEntity rule = new CheckovRuleEntity();

		CheckovProvidedRuleDto ruleDto = new CheckovProvidedRuleDto();
		ruleDto.setPriority(RulePriority.HIGH);
		ruleDto.setId(1L);

		BDDMockito.when(mockRuleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));

		ruleService.editProvidedRule(ruleDto);

		MatcherAssert.assertThat(rule.getPriority(), Matchers.is(ruleDto.getPriority()));
		BDDMockito.verify(mockRuleRepository).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testEditRuleNull() throws Exception {
		CheckovProvidedRuleDto ruleDto = new CheckovProvidedRuleDto();
		ruleDto.setId(1L);

		try {
			ruleService.editProvidedRule(ruleDto);
			Assertions.fail("Should throw Exception");
		} catch (RuleNotFoundException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("No such Checkov Provided rule exists"));
		}
	}
}

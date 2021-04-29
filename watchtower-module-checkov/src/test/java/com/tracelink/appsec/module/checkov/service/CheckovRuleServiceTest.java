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

import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleEntity;
import com.tracelink.appsec.module.checkov.repository.CheckovRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
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
		rule.setCoreRule(true);

		CheckovRuleDto ruleDto = new CheckovRuleDto();
		ruleDto.setPriority(RulePriority.HIGH);
		ruleDto.setId(1L);

		BDDMockito.when(mockRuleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));

		ruleService.editRule(ruleDto);

		MatcherAssert.assertThat(rule.getPriority(), Matchers.is(ruleDto.getPriority()));
		BDDMockito.verify(mockRuleRepository).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testEditRuleNonCore() throws Exception {
		CheckovRuleEntity rule = new CheckovRuleEntity();
		rule.setCoreRule(false);

		CheckovRuleDto ruleDto = new CheckovRuleDto();
		ruleDto.setId(1L);

		BDDMockito.when(mockRuleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		try {
			ruleService.editRule(ruleDto);
			Assertions.fail("Should throw Exception");
		} catch (RuleEditorException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Only supports Core Rules"));
		}
	}

	@Test
	public void testEditRuleNull() throws Exception {
		CheckovRuleDto ruleDto = new CheckovRuleDto();
		ruleDto.setId(1L);

		try {
			ruleService.editRule(ruleDto);
			Assertions.fail("Should throw Exception");
		} catch (RuleNotFoundException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("No such Checkov rule exists"));
		}
	}
}

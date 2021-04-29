package com.tracelink.appsec.module.json.service;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.model.JsonRuleEntity;
import com.tracelink.appsec.module.json.repository.JsonRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@ExtendWith(SpringExtension.class)
public class JsonRuleServiceTest {

	@MockBean
	private JsonRuleRepository ruleRepository;

	private JsonRuleService ruleService;

	@BeforeEach
	public void setup() {
		ruleService = new JsonRuleService(ruleRepository);
	}

	@Test
	public void testGetRule() throws RuleNotFoundException {
		JsonRuleEntity entity = new JsonRuleEntity();
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(entity));
		Assertions.assertEquals(entity, ruleService.getRule(1L));
	}

	@Test
	public void testGetRuleDoesntExist() throws RuleNotFoundException {
		Assertions.assertThrows(RuleNotFoundException.class, () -> {
			BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
					.thenReturn(Optional.empty());
			ruleService.getRule(1L);
		});
	}

	@Test
	public void testEditRule() throws RuleNotFoundException {
		String name = "name";
		String message = "message";
		String extUrl = "http://example";
		RulePriority priority = RulePriority.HIGH;
		String fileExt = "txt";
		String query = "$";
		JsonRuleEntity entity = new JsonRuleEntity();
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(entity));
		JsonRuleDto dto = new JsonRuleDto();
		dto.setId(123L);
		dto.setName(name);
		dto.setMessage(message);
		dto.setExternalUrl(extUrl);
		dto.setPriority(priority);
		dto.setFileExtension(fileExt);
		dto.setQuery(query);
		ruleService.editRule(dto);
		Assertions.assertEquals(name, entity.getName());
		Assertions.assertEquals(message, entity.getMessage());
		Assertions.assertEquals(extUrl, entity.getExternalUrl());
		Assertions.assertEquals(priority, entity.getPriority());
		Assertions.assertEquals(fileExt, entity.getFileExtension());
		Assertions.assertEquals(query, entity.getQuery());
	}

	@Test
	public void testSaveNewRule() throws RuleDesignerException {
		JsonRuleDto mockRule = BDDMockito.mock(JsonRuleDto.class);
		JsonRuleEntity mockEntity = BDDMockito.mock(JsonRuleEntity.class);
		BDDMockito.when(mockRule.toEntity()).thenReturn(mockEntity);
		BDDMockito.when(ruleRepository.findByName(BDDMockito.anyString())).thenReturn(null);
		ruleService.saveNewRule(mockRule);
		ArgumentCaptor<JsonRuleEntity> captor = ArgumentCaptor.forClass(JsonRuleEntity.class);
		BDDMockito.verify(ruleRepository).saveAndFlush(captor.capture());
		Assertions.assertEquals(mockEntity, captor.getValue());
	}

}

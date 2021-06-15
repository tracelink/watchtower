package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;

@ExtendWith(SpringExtension.class)
public class RuleEditorServiceTest {
	@MockBean
	private RuleService ruleService;

	private RuleEditorService ruleEditorService;

	@Mock
	private IRuleEditor mockRuleManager;

	@BeforeEach
	public void setup() {
		ruleEditorService = new RuleEditorService(ruleService);
	}

	@Test
	public void testRegisterRuleEditModuleBlankName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					ruleEditorService.registerRuleEditor("", mockRuleManager);
				});
	}

	@Test
	public void testRegisterRuleEditModuleBlankManager() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					ruleEditorService.registerRuleEditor("mock", null);
				});
	}

	@Test
	public void testRegisterRuleEditModuleDuplicate() throws Exception {
		Assertions.assertThrows(ModuleException.class,
				() -> {
					ruleEditorService.registerRuleEditor("Mock", mockRuleManager);
					ruleEditorService.registerRuleEditor("Mock", mockRuleManager);
				});
	}

	@Test
	public void testGetConfiguredModules() throws Exception {
		ruleEditorService.registerRuleEditor("mock", mockRuleManager);
		MatcherAssert.assertThat(ruleEditorService.getKnownModules(), Matchers.contains("mock"));
	}

	@Test
	public void testGetDefaultRuleEditModule() throws Exception {
		MatcherAssert.assertThat(ruleEditorService.getDefaultRuleEditModule(),
				Matchers.nullValue());
		ruleEditorService.registerRuleEditor("mock", mockRuleManager);
		MatcherAssert.assertThat(ruleEditorService.getDefaultRuleEditModule(), Matchers.is("mock"));
	}

	@Test
	public void testGetRuleEditModelAndView() throws Exception {
		String view = "test";
		String module = "mock";
		Long ruleId = 123L;
		ruleEditorService.registerRuleEditor(module, mockRuleManager);

		RuleDto mockDto = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockDto.getName()).thenReturn("rule");
		BDDMockito.when(mockDto.getModule()).thenReturn(module);
		BDDMockito.when(mockDto.getId()).thenReturn(ruleId);
		BDDMockito.when(ruleService.getRulesForModule(BDDMockito.anyString()))
				.thenReturn(Collections.singletonList(mockDto));

		BDDMockito.when(mockRuleManager.getRuleEditModelAndView(mockDto))
				.thenReturn(new RuleEditModelAndView(view));
		RuleEditModelAndView mav = ruleEditorService.getRuleEditModelAndView(module, ruleId);
		MatcherAssert.assertThat(mav.getModel().get("activeRule"), Matchers.is(mockDto));
		MatcherAssert.assertThat(mav.getModel().get("ruleView"), Matchers.is(view));
		BDDMockito.verify(mockRuleManager).getRuleEditModelAndView(mockDto);
	}

	@Test
	public void testGetRuleEditModelAndViewBlankPage() throws Exception {
		String module = "mock";
		ruleEditorService.registerRuleEditor(module, mockRuleManager);

		RuleEditModelAndView mav = ruleEditorService.getRuleEditModelAndView(module, null);
		MatcherAssert.assertThat(mav.getModel().get("activeRule"), Matchers.nullValue());
		BDDMockito.verify(mockRuleManager, BDDMockito.never())
				.getRuleEditModelAndView(BDDMockito.any());
	}

	@Test
	public void testGetRuleEditModelAndViewUnknownModule() throws Exception {
		Assertions.assertThrows(ModuleNotFoundException.class,
				() -> {
					String module = "mock";
					Long ruleId = 123L;
					ruleEditorService.getRuleEditModelAndView(module, ruleId);
				});
	}

	@Test
	public void testGetRuleEditModelAndViewUnknownRule() throws Exception {
		Assertions.assertThrows(RuleNotFoundException.class,
				() -> {
					String module = "mock";
					Long ruleId = 123L;
					ruleEditorService.registerRuleEditor(module, mockRuleManager);

					RuleDto mockDto = BDDMockito.mock(RuleDto.class);
					BDDMockito.when(mockDto.getName()).thenReturn("rule");
					BDDMockito.when(mockDto.getModule()).thenReturn(module);
					BDDMockito.when(mockDto.getId()).thenReturn(ruleId);

					BDDMockito.when(ruleService.getRulesForModule(BDDMockito.anyString()))
							.thenReturn(Collections.singletonList(mockDto));

					ruleEditorService.getRuleEditModelAndView(module, 234L);
				});
	}
}

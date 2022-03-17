package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import javax.servlet.http.HttpServletResponse;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.mock.MockRuleset;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RulesetsControllerTest {
	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(RulesetsController.class);

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RulesetService rulesetService;
	@MockBean
	private RuleService ruleService;
	@MockBean
	private UserService userService;

	private RulesetEntity defaultRulesetEntity;
	private RulesetDto defaultRuleset;
	private RulesetDto compositeRuleset;

	@BeforeEach
	public void setup() {
		defaultRulesetEntity = MockRuleset.getDefaultRuleset();
		defaultRuleset = MockRuleset.getDefaultRulesetDto();
		compositeRuleset = MockRuleset.getCompositeRulesetDto();
	}

	private String makeUrl(Object id, String... pathParts) {
		if (pathParts != null) {
			String joins = String.join("/", pathParts);
			return "/rulesets/" + id + "/" + joins;
		}
		return "/rulesets/" + id + "/";
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesets() throws Exception {
		BDDMockito.when(rulesetService.getDefaultRuleset())
				.thenReturn(defaultRulesetEntity);
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets"))
				.andExpect(
						MockMvcResultMatchers
								.redirectedUrl(makeUrl(defaultRulesetEntity.getId())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsEmptyRulesets() throws Exception {
		BDDMockito.when(rulesetService.getDefaultRuleset()).thenReturn(null);
		BDDMockito.when(rulesetService.getRulesets()).thenReturn(Collections.emptyList());
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(makeUrl(-1)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsNoDefaultRuleset() throws Exception {
		BDDMockito.when(rulesetService.getDefaultRuleset()).thenReturn(null);
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Arrays.asList(compositeRuleset, defaultRuleset));
		mockMvc.perform(
				MockMvcRequestBuilders.get("/rulesets"))
				.andExpect(
						MockMvcResultMatchers
								.redirectedUrl(makeUrl(compositeRuleset.getId())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testCreateRuleset() throws Exception {
		BDDMockito
				.when(rulesetService.createRuleset(defaultRuleset.getName(),
						defaultRuleset.getDescription(), RulesetDesignation.PRIMARY))
				.thenReturn(new RulesetEntity());
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl("create"))
						.param("name", defaultRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "PRIMARY")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully created ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testCreateRulesetNameCollision() throws Exception {
		BDDMockito
				.when(rulesetService.createRuleset(defaultRuleset.getName(),
						defaultRuleset.getDescription(), RulesetDesignation.SUPPORTING))
				.thenThrow(RulesetException.class);
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl("create"))
						.param("name", defaultRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot create ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testCreateRulesetProvided() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl("create"))
						.param("name", defaultRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "PROVIDED")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot create a provided ruleset")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetDefaultRuleset() throws Exception {
		BDDMockito
				.when(rulesetService.setDefaultRuleset(compositeRuleset.getId()))
				.thenReturn(defaultRulesetEntity);
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl("default"))
						.param("rulesetId", compositeRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully set the default ruleset."))
				.andExpect(
						MockMvcResultMatchers.redirectedUrl(makeUrl(defaultRulesetEntity.getId())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetDefaultRulesetError() throws Exception {
		BDDMockito.doThrow(RulesetException.class).when(rulesetService)
				.setDefaultRuleset(compositeRuleset.getId());
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl("default"))
						.param("rulesetId", compositeRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot set the default ruleset.")));
	}


	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsView() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Arrays.asList(compositeRuleset, defaultRuleset));
		mockMvc.perform(
				MockMvcRequestBuilders.get(makeUrl(compositeRuleset.getId())))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("currentRuleset", Matchers.is(compositeRuleset)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsViewBadId() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Arrays.asList(compositeRuleset, defaultRuleset));
		mockMvc.perform(
				MockMvcRequestBuilders.get(makeUrl(600)))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Could not find a ruleset")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_IMPEX_NAME})
	public void testImportRuleset() throws Exception {
		BDDMockito.when(rulesetService.importRuleset(BDDMockito.any(), BDDMockito.anyString()))
				.thenReturn(defaultRuleset);
		mockMvc.perform(
				MockMvcRequestBuilders.multipart(makeUrl("import"))
						.file(new MockMultipartFile("file", "bytes".getBytes()))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Successfully imported ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_IMPEX_NAME})
	public void testImportRulesetJsonExceptionThrown() throws Exception {
		BDDMockito.willThrow(JsonProcessingException.class)
				.given(rulesetService).importRuleset(BDDMockito.any(), BDDMockito.anyString());
		mockMvc.perform(
				MockMvcRequestBuilders.multipart(makeUrl("import"))
						.file(new MockMultipartFile("file", "bytes".getBytes()))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot import ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_IMPEX_NAME})
	public void testImportRulesetExceptionThrown() throws Exception {
		BDDMockito.willThrow(IOException.class)
				.given(rulesetService).importRuleset(BDDMockito.any(), BDDMockito.anyString());
		mockMvc.perform(
				MockMvcRequestBuilders.multipart(makeUrl("import"))
						.file(new MockMultipartFile("file", "bytes".getBytes()))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot import ruleset.")));
	}


	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetRules() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(compositeRuleset.getId(), "rules"))
						.param("ruleIds", "1", "2")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully set rules."));

		BDDMockito.verify(rulesetService).setRules(compositeRuleset.getId(), Arrays.asList(1L, 2L));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetRulesRulesetNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.setRules(compositeRuleset.getId(), Arrays.asList(1L, 2L));
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(compositeRuleset.getId(), "rules"))
						.param("ruleIds", "1", "2")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot set rules.")));

		BDDMockito.verify(rulesetService).setRules(compositeRuleset.getId(), Arrays.asList(1L, 2L));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetRulesEmptyRules() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(compositeRuleset.getId(), "rules"))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Successfully set rules.")));

		BDDMockito.verify(rulesetService).setRules(compositeRuleset.getId(),
				Collections.emptyList());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_IMPEX_NAME})
	public void testExportRuleset() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "export"))
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(rulesetService, Mockito.times(1))
				.exportRuleset(BDDMockito.anyLong(), BDDMockito.any(HttpServletResponse.class));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_IMPEX_NAME})
	public void testExportRulesetErrorConverting() throws Exception {
		BDDMockito.doThrow(JsonProcessingException.class).when(rulesetService)
				.exportRuleset(BDDMockito.anyLong(), BDDMockito.any(HttpServletResponse.class));

		mockMvc.perform(MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "export"))
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertTrue(logWatcher.getMessages().get(0)
				.contains("Error exporting ruleset with ID: " + defaultRuleset.getId()));
	}


	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDeleteRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "delete"))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully deleted ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDeleteRulesetNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.deleteRuleset(defaultRuleset.getId());
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "delete"))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot delete ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testEditRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "edit"))
						.param("name", MockRuleset.COMPOSITE_RULESET_NAME)
						.param("description", MockRuleset.COMPOSITE_RULESET_DESCRIPTION)
						.param("designation", "PRIMARY")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully edited ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testEditRulesetBindingError() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "edit"))
						.param("name", "").param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING").param("blockingPriority", "HIGH")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot edit ruleset. Name cannot be empty.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testEditRulesetDifferentRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "edit"))
						.param("name", MockRuleset.COMPOSITE_RULESET_NAME)
						.param("id", "123")
						.param("description", MockRuleset.COMPOSITE_RULESET_DESCRIPTION)
						.param("designation", "PRIMARY")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit a different ruleset")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testEditRulesetNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.editRuleset(BDDMockito.any(RulesetDto.class));
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(defaultRuleset.getId(), "edit"))
						.param("name", compositeRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING").param("blockingPriority", "HIGH")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot edit ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetInheritedRulesets() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(compositeRuleset.getId(), "inherit"))
						.param("inheritedRulesetIds", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully set inherited rulesets."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetInheritedRulesetsNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.setInheritedRulesets(compositeRuleset.getId(),
						Collections.singletonList(defaultRuleset.getId()));
		mockMvc.perform(
				MockMvcRequestBuilders.post(makeUrl(compositeRuleset.getId(), "inherit"))
						.param("inheritedRulesetIds", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot set inherited rulesets.")));
	}


}

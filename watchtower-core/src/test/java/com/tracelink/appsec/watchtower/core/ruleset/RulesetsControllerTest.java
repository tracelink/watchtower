package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import org.springframework.core.io.InputStreamResource;
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
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.mock.MockRule;
import com.tracelink.appsec.watchtower.core.mock.MockRuleset;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RulesetsControllerTest {
	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(RulesetsController.class);

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RulesetService rulesetService;
	@MockBean
	private RuleService ruleService;
	@MockBean
	private UserService userService;

	private RulesetDto defaultRuleset;
	private RulesetDto compositeRuleset;
	private RuleDto ruleDto;

	@BeforeEach
	public void setup() {
		defaultRuleset = MockRuleset.getDefaultRulesetDto();
		compositeRuleset = MockRuleset.getCompositeRulesetDto();
		ruleDto = new MockRule().toDto();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesets() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Collections.singletonList(defaultRuleset));
		BDDMockito.when(ruleService.getRules()).thenReturn(Collections.singletonList(ruleDto));
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets"))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.contains(defaultRuleset)))
				.andExpect(MockMvcResultMatchers.model().attribute("rules",
						Matchers.contains(ruleDto)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						defaultRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsEmptyRulesets() throws Exception {
		BDDMockito.when(rulesetService.getRulesets()).thenReturn(Collections.emptyList());
		BDDMockito.when(ruleService.getRules()).thenReturn(Collections.emptyList());
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets"))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.iterableWithSize(0)))
				.andExpect(MockMvcResultMatchers.model().attribute("rules",
						Matchers.iterableWithSize(0)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						Matchers.nullValue()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testGetRulesetsActiveRuleset() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Arrays.asList(defaultRuleset, compositeRuleset));
		BDDMockito.when(ruleService.getRules()).thenReturn(Collections.emptyList());
		mockMvc.perform(
				MockMvcRequestBuilders.get("/rulesets")
						.param("activeRuleset", compositeRuleset.getId().toString()))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("rulesets", Matchers.contains(defaultRuleset, compositeRuleset)))
				.andExpect(MockMvcResultMatchers.model().attribute("rules",
						Matchers.iterableWithSize(0)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						compositeRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testSetRules() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rulesets")
						.param("rulesetId", compositeRuleset.getId().toString())
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
				MockMvcRequestBuilders.post("/rulesets")
						.param("rulesetId", compositeRuleset.getId().toString())
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
				MockMvcRequestBuilders.post("/rulesets")
						.param("rulesetId", compositeRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Successfully set rules.")));

		BDDMockito.verify(rulesetService).setRules(compositeRuleset.getId(),
				Collections.emptyList());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testImportRuleset() throws Exception {
		defaultRuleset.setRules(Collections.singleton(ruleDto));
		MockMultipartFile mockFile = new MockMultipartFile("file", "mock.xml", "text/xml",
				"<mock>Mock Data</mock>".getBytes());
		mockMvc.perform(
				MockMvcRequestBuilders.multipart("/rulesets/import").file(mockFile)
						.param("ruleType", "mock")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Successfully imported ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testImportRulesetJsonExceptionThrown() throws Exception {
		MockMultipartFile mockFile = new MockMultipartFile("file", "mock.xml", "text/xml",
				"<mock>Mock Data</mock>".getBytes());
		UserEntity user = new UserEntity();
		BDDMockito.when(userService.findByUsername(BDDMockito.anyString())).thenReturn(user);
		BDDMockito.willThrow(JsonProcessingException.class).given(rulesetService)
				.importRuleset(BDDMockito.anyString(), BDDMockito.any(InputStream.class),
						BDDMockito.any(UserEntity.class));
		mockMvc.perform(
				MockMvcRequestBuilders.multipart("/rulesets/import").file(mockFile)
						.param("ruleType", "mock")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot import ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testImportRulesetExceptionThrown() throws Exception {
		MockMultipartFile mockFile = new MockMultipartFile("file", "mock.xml", "text/xml",
				"<mock>Mock Data</mock>".getBytes());
		UserEntity user = new UserEntity();
		BDDMockito.when(userService.findByUsername(BDDMockito.anyString())).thenReturn(user);
		BDDMockito.willThrow(IOException.class).given(rulesetService)
				.importRuleset(BDDMockito.anyString(), BDDMockito.any(InputStream.class),
						BDDMockito.any(UserEntity.class));
		mockMvc.perform(
				MockMvcRequestBuilders.multipart("/rulesets/import").file(mockFile)
						.param("ruleType", "mock")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot import ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testExportRuleset() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rulesets/export")
				.param("rulesetId", defaultRuleset.getId().toString())
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(rulesetService, Mockito.times(1))
				.exportRuleset(BDDMockito.anyLong(), BDDMockito.any(HttpServletResponse.class));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	public void testExportRulesetErrorConverting() throws Exception {
		BDDMockito.doThrow(JsonProcessingException.class).when(rulesetService)
				.exportRuleset(BDDMockito.anyLong(), BDDMockito.any(HttpServletResponse.class));

		mockMvc.perform(MockMvcRequestBuilders.post("/rulesets/export")
				.param("rulesetId", defaultRuleset.getId().toString())
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertTrue(logWatcher.getMessages().get(0)
				.contains("Error exporting ruleset with ID: " + defaultRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDownloadExample() throws Exception {
		byte[] buf = "test".getBytes();
		InputStreamResource isr = new InputStreamResource(new ByteArrayInputStream(buf));
		BDDMockito.when(rulesetService.downloadExampleRuleset(BDDMockito.anyString()))
				.thenReturn(isr);
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets/import/example")
				.param("ruleType", "foo")).andExpect(MockMvcResultMatchers.content().bytes(buf));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDownloadExampleNoResource() throws Exception {
		BDDMockito.when(rulesetService.downloadExampleRuleset(BDDMockito.anyString()))
				.thenReturn(null);
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets/import/example")
				.param("ruleType", "foo"))
				.andExpect(r -> r.getResolvedException().getMessage()
						.contains("Cannot Export Example"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDownloadExampleException() throws Exception {
		BDDMockito.willThrow(new RulesetInterpreterException("Exception"))
				.given(rulesetService).downloadExampleRuleset(BDDMockito.anyString());
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets/import/example")
				.param("ruleType", "foo")).andExpect(
						r -> r.getResolvedException().getMessage()
								.contains("Exception"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testDownloadExampleBadInput() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/rulesets/import/example")
				.param("ruleType", ""))
				.andExpect(r -> r.getResolvedException().getMessage()
						.contains("No Rule Type"));
	}
}

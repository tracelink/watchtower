package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.Arrays;
import java.util.Collections;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRuleset;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RulesetMgmtControllerTest {
	private static final String DEFAULT_DESC = "Default ruleset to run with Watchtower.";
	private static final String COMPOSITE = "Composite";
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RulesetService rulesetService;

	private RulesetDto defaultRuleset;
	private RulesetDto compositeRuleset;

	@BeforeEach
	public void setup() {
		defaultRuleset = MockRuleset.getDefaultRulesetDto();
		compositeRuleset = MockRuleset.getCompositeRulesetDto();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testGetRulesetMgmt() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Collections.singletonList(defaultRuleset));
		mockMvc.perform(MockMvcRequestBuilders.get("/ruleset/mgmt"))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.contains(defaultRuleset)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						defaultRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testGetRulesetMgmtEmptyRulesets() throws Exception {
		BDDMockito.when(rulesetService.getRulesets()).thenReturn(Collections.emptyList());
		mockMvc.perform(MockMvcRequestBuilders.get("/ruleset/mgmt"))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.iterableWithSize(0)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						Matchers.nullValue()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testGetRulesetMgmtActiveRuleset() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Arrays.asList(defaultRuleset, compositeRuleset));
		mockMvc.perform(
				MockMvcRequestBuilders.get("/ruleset/mgmt").param("activeRuleset",
						compositeRuleset.getId().toString()))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("rulesets", Matchers.contains(defaultRuleset, compositeRuleset)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						compositeRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testGetRulesetMgmtActiveValueNotPresent() throws Exception {
		BDDMockito.when(rulesetService.getRulesets())
				.thenReturn(Collections.singletonList(defaultRuleset));
		mockMvc.perform(MockMvcRequestBuilders.get("/ruleset/mgmt").param("activeRuleset", "2"))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.contains(defaultRuleset)))
				.andExpect(MockMvcResultMatchers.model().attribute("activeRuleset",
						defaultRuleset.getId()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testCreateRuleset() throws Exception {
		BDDMockito
				.when(rulesetService.createRuleset(defaultRuleset.getName(),
						defaultRuleset.getDescription(),
						RulesetDesignation.PRIMARY))
				.thenReturn(new RulesetEntity());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/create")
						.param("name", defaultRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "PRIMARY")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully created ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testCreateRulesetNameCollision() throws Exception {
		BDDMockito
				.when(rulesetService.createRuleset(defaultRuleset.getName(),
						defaultRuleset.getDescription(),
						RulesetDesignation.SUPPORTING))
				.thenThrow(RulesetException.class);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/create")
						.param("name", defaultRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot create ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testDeleteRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/delete")
						.param("rulesetId", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully deleted ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testDeleteRulesetNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.deleteRuleset(BDDMockito.anyLong());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/delete")
						.param("rulesetId", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot delete ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testEditRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/edit")
						.param("id", defaultRuleset.getId().toString())
						.param("name", COMPOSITE).param("description", DEFAULT_DESC)
						.param("designation", "PRIMARY")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully edited ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testEditRulesetBindingError() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/edit")
						.param("id", defaultRuleset.getId().toString())
						.param("name", "").param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING").param("blockingPriority", "HIGH")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot edit ruleset. Name cannot be empty.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testEditRulesetNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.editRuleset(BDDMockito.any(RulesetDto.class));
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/edit")
						.param("id", defaultRuleset.getId().toString())
						.param("name", compositeRuleset.getName())
						.param("description", defaultRuleset.getDescription())
						.param("designation", "SUPPORTING").param("blockingPriority", "HIGH")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot edit ruleset.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testSetInheritedRulesets() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/inherit")
						.param("rulesetId", compositeRuleset.getId().toString())
						.param("inheritedRulesetIds", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully set inherited rulesets."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testSetInheritedRulesetsNotFound() throws Exception {
		BDDMockito.doThrow(RulesetNotFoundException.class).when(rulesetService)
				.setInheritedRulesets(compositeRuleset.getId(),
						Collections.singletonList(defaultRuleset.getId()));
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/inherit")
						.param("rulesetId", compositeRuleset.getId().toString())
						.param("inheritedRulesetIds", defaultRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot set inherited rulesets.")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testSetDefaultRuleset() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/default")
						.param("rulesetId", compositeRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully set the default ruleset."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESET_MGMT_MODIFY_NAME})
	public void testSetDefaultRulesetError() throws Exception {
		BDDMockito.doThrow(RulesetException.class).when(rulesetService)
				.setDefaultRuleset(compositeRuleset.getId());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/ruleset/mgmt/default")
						.param("rulesetId", compositeRuleset.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot set the default ruleset.")));
	}
}

package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
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
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepositoryControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ScmRepositoryService mockRepoService;

	@MockBean
	private RulesetService mockRulesetService;

	///////////////////
	// Get repository
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.REPO_SETTINGS_VIEW_NAME})
	public void testGetRepos() throws Exception {
		Map<String, List<ScmRepositoryEntity>> repos = new LinkedHashMap<>();
		List<ScmRepositoryEntity> entities = new ArrayList<>();
		entities.add(BDDMockito.mock(ScmRepositoryEntity.class));
		repos.put("ApiLabel", entities);

		BDDMockito.when(mockRepoService.getAllRepos()).thenReturn(repos);
		mockMvc.perform(MockMvcRequestBuilders.get("/repository"))
				.andExpect(MockMvcResultMatchers.model().attribute("repos", Matchers.is(repos)));
	}

	///////////////////
	// Post repository
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void testSetRulesetForRepoSuccess() throws Exception {
		String apiLabel = ScmApiType.BITBUCKET_CLOUD.getTypeName();
		String repo = "repo";
		RulesetEntity rulesetEntity = new RulesetEntity();
		rulesetEntity.setName("Default");
		BDDMockito.when(mockRulesetService.getRuleset(1L)).thenReturn(rulesetEntity);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/repository").param("apiLabel", apiLabel)
						.param("repo", repo)
						.param("rulesetId", "1").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockRepoService).setRulesetForRepo(1L, apiLabel, "repo");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void testSetRulesetForRepoApiFailure() throws Exception {
		String apiLabel = "ThisIsWrong";
		String repo = "repo";
		BDDMockito.willThrow(RulesetNotFoundException.class)
				.given(mockRepoService).setRulesetForRepo(BDDMockito.anyLong(),
						BDDMockito.anyString(), BDDMockito.anyString());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/repository").param("apiLabel", apiLabel)
						.param("repo", repo)
						.param("rulesetId", "1").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot set ruleset")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void testSetRulesetForRepoRulesetFailure() throws Exception {
		String apiLabel = ScmApiType.BITBUCKET_CLOUD.getTypeName();
		String repo = "repo";
		BDDMockito.doThrow(RulesetNotFoundException.class).when(mockRepoService)
				.setRulesetForRepo(BDDMockito.anyLong(), BDDMockito.anyString(),
						BDDMockito.anyString());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/repository").param("apiLabel", apiLabel)
						.param("repo", repo)
						.param("rulesetId", "1").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot set ruleset.")));
	}
}

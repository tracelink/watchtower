package com.tracelink.appsec.watchtower.core.rule.draft;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;

/** Opening a designer from a draft, and throwing a draft away. */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class RuleDesignerDraftMvcTest {
	private static final String ID = "5d1c5a0e-0000-4000-8000-000000000001";
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private RuleDesignerService designers;
	@MockitoBean
	private RuleDraftService drafts;

	private static RuleDraftData draft() {
		return new RuleDraftData(ID, "regex", null, "No string-built SQL", "m", 2, "CWE-89", "CWE-564", "x+", null,
				"select ' + id", "select ?", "Concatenating input into SQL lets it change the query.", "Coverage gap: CWE-89 · Java");
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void aDraftOpensTheDesignerWithItsRuleFilledInAndABanner() throws Exception {
		when(drafts.open(ID, "alice", "regex")).thenReturn(Optional.of(draft()));
		when(designers.getPrefilledDesignerModelAndView(eq("regex"), any())).thenReturn(new RuleDesignerModelAndView(null));
		when(designers.getKnownModulesForUser(any())).thenReturn(List.of("regex"));

		var result = mockMvc.perform(get("/designer/regex").param("draft", ID)).andExpect(status().isOk())
				.andExpect(model().attribute("draftBanner", Matchers.instanceOf(RuleDraftBanner.class))).andReturn();

		var banner = (RuleDraftBanner) result.getModelAndView().getModel().get("draftBanner");
		org.assertj.core.api.Assertions.assertThat(banner.cwe()).isEqualTo("CWE-89, CWE-564");
		org.assertj.core.api.Assertions.assertThat(banner.discardUrl()).isEqualTo("/designer/draft/" + ID + "/discard");
		org.assertj.core.api.Assertions.assertThat(banner.tip()).contains("Nothing is saved").contains("Coverage gap: CWE-89");
		verify(designers, never()).getDefaultDesignerModelAndView(anyString());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void aDraftThatIsGoneOpensThePlainDesignerAndSaysSo() throws Exception {
		when(drafts.open(ID, "alice", "regex")).thenReturn(Optional.empty());
		when(designers.getDefaultDesignerModelAndView("regex")).thenReturn(new RuleDesignerModelAndView(null));
		when(designers.getKnownModulesForUser(any())).thenReturn(List.of("regex"));

		mockMvc.perform(get("/designer/regex").param("draft", ID)).andExpect(status().isOk())
				.andExpect(model().attributeDoesNotExist("draftBanner"))
				.andExpect(model().attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, Matchers.containsString("no longer available")));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void withoutADraftTheDesignerIsAsBefore() throws Exception {
		when(designers.getDefaultDesignerModelAndView("regex")).thenReturn(new RuleDesignerModelAndView(null));
		when(designers.getKnownModulesForUser(any())).thenReturn(List.of("regex"));

		mockMvc.perform(get("/designer/regex")).andExpect(status().isOk()).andExpect(model().attributeDoesNotExist("draftBanner"));

		verify(drafts, never()).open(any(), any(), any());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void discardingGoesBackToThePlainDesignerOfThatScanner() throws Exception {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft()));
		when(drafts.discard(ID, "alice")).thenReturn(true);

		mockMvc.perform(post("/designer/draft/" + ID + "/discard").with(csrf())).andExpect(redirectedUrl("/designer/regex"))
				.andExpect(flash().attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Draft discarded."));
	}

	@Test
	@WithMockUser(username = "mallory", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void anotherPersonsDraftCannotBeDiscarded() throws Exception {
		when(drafts.ownedOpen(ID, "mallory")).thenReturn(Optional.empty());

		mockMvc.perform(post("/designer/draft/" + ID + "/discard").with(csrf())).andExpect(redirectedUrl("/designer"))
				.andExpect(flash().attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, Matchers.containsString("no longer available")));

		verify(drafts, never()).discard(any(), any());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	void discardingNeedsCsrf() throws Exception {
		mockMvc.perform(post("/designer/draft/" + ID + "/discard")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	void discardingNeedsTheDesignerAuthority() throws Exception {
		mockMvc.perform(post("/designer/draft/" + ID + "/discard").with(csrf())).andExpect(status().isForbidden());
	}
}

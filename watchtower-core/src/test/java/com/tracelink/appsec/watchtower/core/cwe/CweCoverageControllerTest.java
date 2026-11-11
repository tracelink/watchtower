package com.tracelink.appsec.watchtower.core.cwe;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
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

/** The coverage endpoints: who may read or change, what they answer and how a refused input looks. */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class CweCoverageControllerTest {
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private CweCoverageService coverage;
	@MockitoBean
	private CweProfileService profile;
	@MockitoBean
	private CweCatalogService catalog;
	@MockitoBean
	private CweStarterMapService starter;

	@BeforeEach
	void setUp() {
		var counts = new CweCoverageService.Counts(1, 2, 3, 4);
		when(coverage.coverage()).thenReturn(new CweCoverageService.Coverage(
				List.of(new CweCoverageService.Column("JAVA", "Java / Spring")), List.of(), counts, true));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	void aReaderGetsTheTable() throws Exception {
		mockMvc.perform(get("/rules/coverage")).andExpect(status().isOk()).andExpect(jsonPath("$.counts.gap").value(3))
				.andExpect(jsonPath("$.columns[0].key").value("JAVA")).andExpect(jsonPath("$.catalogLoaded").value(true));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	void searchAnswersWithShortRowsAndCutsALongQuery() throws Exception {
		var entry = new CweEntry(74, "Injection", "Class", "Simple", "Stable", "Discouraged", "d", null, List.of());
		when(catalog.search(any(), eq(10))).thenReturn(List.of(entry));

		mockMvc.perform(get("/rules/coverage/search").param("q", "x".repeat(500))).andExpect(status().isOk())
				.andExpect(jsonPath("$[0].label").value("CWE-74")).andExpect(jsonPath("$[0].discouraged").value(true));

		verify(catalog).search("x".repeat(80), 10);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	void aReaderCannotChangeAnything() throws Exception {
		mockMvc.perform(post("/rules/coverage/profile").param("cwe", "CWE-89").with(csrf())).andExpect(status().isForbidden());
		mockMvc.perform(post("/rules/coverage/profile/top25").with(csrf())).andExpect(status().isForbidden());
		mockMvc.perform(post("/rules/coverage/decision").param("cwe", "CWE-89").param("language", "JAVA")
				.param("decision", "DEFERRED").with(csrf())).andExpect(status().isForbidden());

		verify(profile, never()).add(any(), any(), any(), any());
		verify(profile, never()).addTop25(any());
		verify(profile, never()).decide(any(), any(), any(), any(), any());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULESETS_VIEW_NAME})
	void aChangeNeedsCsrf() throws Exception {
		mockMvc.perform(post("/rules/coverage/profile").param("cwe", "CWE-89")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULESETS_VIEW_NAME})
	void anEditorChangesTheProfileAndGetsTheNewTable() throws Exception {
		mockMvc.perform(post("/rules/coverage/profile").param("cwe", "CWE-89").param("priority", "CRITICAL")
				.param("note", "biggest risk").with(csrf())).andExpect(status().isOk()).andExpect(jsonPath("$.counts.covered").value(1));
		mockMvc.perform(post("/rules/coverage/profile/remove").param("cwe", "CWE-89").with(csrf())).andExpect(status().isOk());
		mockMvc.perform(post("/rules/coverage/decision").param("cwe", "CWE-89").param("language", "PYTHON")
				.param("decision", "NOT_COVERABLE").param("note", "needs taint tracking").with(csrf())).andExpect(status().isOk());
		mockMvc.perform(post("/rules/coverage/decision/clear").param("cwe", "CWE-89").param("language", "PYTHON").with(csrf()))
				.andExpect(status().isOk());

		verify(profile).add("CWE-89", "CRITICAL", "biggest risk", "alice");
		verify(profile).remove("CWE-89");
		verify(profile).decide("CWE-89", "PYTHON", "NOT_COVERABLE", "needs taint tracking", "alice");
		verify(profile).clearDecision("CWE-89", "PYTHON");
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULESETS_VIEW_NAME})
	void theTop25ButtonSaysHowManyWereAdded() throws Exception {
		when(profile.addTop25("alice")).thenReturn(25);

		mockMvc.perform(post("/rules/coverage/profile/top25").with(csrf())).andExpect(status().isOk())
				.andExpect(jsonPath("$.added").value(25)).andExpect(jsonPath("$.coverage.counts.weak").value(2));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULESETS_VIEW_NAME})
	void theStarterMapIsPreviewedThenApplied() throws Exception {
		var proposal = new CweStarterMapService.Proposal(7, "EmptyCatchBlock", "pmd", "CWE-390", "Detection of Error Condition Without Action");
		when(starter.preview()).thenReturn(new CweStarterMapService.Preview(List.of(proposal), 1));
		when(starter.apply("alice")).thenReturn(1);

		mockMvc.perform(get("/rules/coverage/starter")).andExpect(status().isOk())
				.andExpect(jsonPath("$.proposals[0].cwe").value("CWE-390")).andExpect(jsonPath("$.skippedUnknownCwe").value(1));
		mockMvc.perform(post("/rules/coverage/starter").with(csrf())).andExpect(status().isOk())
				.andExpect(jsonPath("$.changed").value(1)).andExpect(jsonPath("$.coverage.counts.gap").value(3));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_VIEW_NAME})
	void aReaderCannotUseTheStarterMap() throws Exception {
		mockMvc.perform(get("/rules/coverage/starter")).andExpect(status().isForbidden());
		mockMvc.perform(post("/rules/coverage/starter").with(csrf())).andExpect(status().isForbidden());

		verify(starter, never()).apply(any());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULESETS_VIEW_NAME})
	void aRefusedInputIsABadRequestWithTheMessage() throws Exception {
		when(profile.add(any(), any(), any(), any())).thenThrow(new IllegalArgumentException("Enter a CWE number, like CWE-79."));

		mockMvc.perform(post("/rules/coverage/profile").param("cwe", "nope").with(csrf())).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("Enter a CWE number, like CWE-79."));
	}
}

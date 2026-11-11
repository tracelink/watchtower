package com.tracelink.appsec.watchtower.core.assistant.review;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSettingsService;

/** The AI review endpoints: who may use them, what they answer, and how a refusal looks. */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class AiReviewControllerTest {
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private AiReviewService review;
	/** The assistant routes answer 503 until the assistant is available; these tests are about the routes, not that gate. */
	@MockitoBean
	private AssistantSettingsService settings;

	@BeforeEach
	void assistantIsAvailable() {
		when(settings.available()).thenReturn(true);
	}

	@Test
	@WithMockUser(username = "alice", authorities = { "Assistant Use" })
	void filesRunsAndTheLatestReviewAreRead() throws Exception {
		when(review.candidates("alice", "pull_request", 7)).thenReturn(Map.of("state", "OK", "max_files", 10));
		when(review.latest("alice", "repository", 5)).thenReturn(Map.of("state", "NONE"));
		when(review.view("alice", "r1")).thenReturn(Map.of("state", "DONE", "run_id", "r1"));

		mockMvc.perform(get("/assistant/ai-review/files/pull_request/7")).andExpect(status().isOk()).andExpect(jsonPath("$.max_files").value(10));
		mockMvc.perform(get("/assistant/ai-review/scan/repository/5")).andExpect(status().isOk()).andExpect(jsonPath("$.state").value("NONE"));
		mockMvc.perform(get("/assistant/ai-review/runs/r1")).andExpect(status().isOk()).andExpect(jsonPath("$.run_id").value("r1"));
	}

	@Test
	@WithMockUser(username = "alice", authorities = { "Assistant Use" })
	void startingAReviewIsAcceptedWithCsrfAndTheChosenFiles() throws Exception {
		when(review.start("alice", "pull_request", 7, List.of("src/A.java", "src/B.java"), null)).thenReturn(Map.of("state", "QUEUED", "run_id", "r1"));

		mockMvc.perform(post("/assistant/ai-review").with(csrf()).contentType(MediaType.APPLICATION_JSON)
				.content("{\"scanType\":\"pull_request\",\"scanId\":7,\"paths\":[\"src/A.java\",\"src/B.java\"]}"))
				.andExpect(status().isAccepted()).andExpect(jsonPath("$.run_id").value("r1"));
		mockMvc.perform(post("/assistant/ai-review").contentType(MediaType.APPLICATION_JSON).content("{\"scanType\":\"pull_request\",\"scanId\":7}"))
				.andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(username = "alice", authorities = { "Assistant Use" })
	void aFocusInTheRequestIsPassedOnAndAMissingOneIsNone() throws Exception {
		when(review.start("alice", "repository", 12, List.of("src/A.java"), "input validation")).thenReturn(Map.of("state", "QUEUED", "run_id", "r2"));

		mockMvc.perform(post("/assistant/ai-review").with(csrf()).contentType(MediaType.APPLICATION_JSON)
				.content("{\"scanType\":\"repository\",\"scanId\":12,\"paths\":[\"src/A.java\"],\"focus\":\"input validation\"}"))
				.andExpect(status().isAccepted()).andExpect(jsonPath("$.run_id").value("r2"));

		verify(review).start("alice", "repository", 12, List.of("src/A.java"), "input validation");
	}

	@Test
	@WithMockUser(username = "alice", authorities = { "Assistant Use" })
	void aRefusalIsABadRequestWithTheMessage() throws Exception {
		when(review.start(anyString(), anyString(), anyLong(), any(), any())).thenThrow(new IllegalArgumentException("Choose between 1 and 200 files."));

		mockMvc.perform(post("/assistant/ai-review").with(csrf()).contentType(MediaType.APPLICATION_JSON)
				.content("{\"scanType\":\"pull_request\",\"scanId\":7,\"paths\":[]}")).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("Choose between 1 and 200 files."));
		mockMvc.perform(post("/assistant/ai-review").with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"paths\":[\"A.java\"]}"))
				.andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("scanType and scanId are required"));
	}

	@Test
	@WithMockUser(username = "alice", authorities = { "Assistant Use" })
	void aStoppedReviewCanBeResumedAndAPointDecidedOrDraftedWithCsrf() throws Exception {
		when(review.resume("alice", "r1")).thenReturn(Map.of("state", "QUEUED"));
		when(review.act("alice", "i1", "dismiss")).thenReturn(Map.of("state", "OK"));
		when(review.act("alice", "i1", "draft")).thenReturn(Map.of("state", "OK", "url", "/designer/pmd?draft=x"));

		mockMvc.perform(post("/assistant/ai-review/runs/r1/resume").with(csrf())).andExpect(status().isAccepted());
		mockMvc.perform(post("/assistant/ai-review/items/i1/dismiss").with(csrf())).andExpect(status().isOk()).andExpect(jsonPath("$.state").value("OK"));
		mockMvc.perform(post("/assistant/ai-review/items/i1/draft").with(csrf())).andExpect(status().isOk()).andExpect(jsonPath("$.url").value("/designer/pmd?draft=x"));
		mockMvc.perform(post("/assistant/ai-review/items/i1/dismiss")).andExpect(status().isForbidden());
		mockMvc.perform(post("/assistant/ai-review/runs/r1/resume")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(username = "mallory", authorities = { "Ruleset View" })
	void withoutAssistantUseNothingIsReachable() throws Exception {
		mockMvc.perform(get("/assistant/ai-review/files/pull_request/7")).andExpect(status().isForbidden());
		mockMvc.perform(post("/assistant/ai-review").with(csrf()).contentType(MediaType.APPLICATION_JSON)
				.content("{\"scanType\":\"pull_request\",\"scanId\":7,\"paths\":[\"A.java\"]}")).andExpect(status().isForbidden());
		mockMvc.perform(post("/assistant/ai-review/items/i1/confirm").with(csrf())).andExpect(status().isForbidden());

		verify(review, never()).start(anyString(), anyString(), anyLong(), any(), any());
		verify(review, never()).act(anyString(), anyString(), anyString());
	}
}

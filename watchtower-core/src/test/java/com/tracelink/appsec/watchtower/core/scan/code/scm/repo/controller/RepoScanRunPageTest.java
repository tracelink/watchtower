package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import java.util.List;
import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobRepository;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.ExpandPlanHandler;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/** A run with no scans says why, instead of "Preparing this run" for ever. */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepoScanRunPageTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RepoScanRepository scans;

	@MockitoBean
	private RepoScanPlanRepository plans;

	@MockitoBean
	private AsyncJobRepository jobs;

	private void givenPlanWithNoScans() {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("label:e2e-none");
		plan.setApiLabel("Bitbucket2");
		ReflectionTestUtils.setField(plan, "id", 7L);
		BDDMockito.when(plans.findById(7L)).thenReturn(Optional.of(plan));
		BDDMockito.when(scans.findRun(7L, 1)).thenReturn(List.of());
	}

	private void givenPreparationJob(AsyncJobStatus status) {
		AsyncJobEntity job = new AsyncJobEntity();
		job.setType(AsyncJobType.EXPAND_PLAN);
		job.setStatus(status);
		BDDMockito.when(jobs.findFirstByTypeAndPayloadOrderByIdDesc(AsyncJobType.EXPAND_PLAN,
				ExpandPlanHandler.payload(7L, 1))).thenReturn(job);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void aRunStillBeingPreparedSaysSoAndKeepsRefreshing() throws Exception {
		givenPlanWithNoScans();
		givenPreparationJob(AsyncJobStatus.RUNNING);

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/run/7/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Preparing this run"),
						Matchers.containsString("hx-get=\"/reposcan/run/7/1\""))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void aRunWhoseSelectionMatchedNothingSaysThatAndStopsRefreshing() throws Exception {
		givenPlanWithNoScans();
		givenPreparationJob(AsyncJobStatus.DONE);

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/run/7/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Nothing matched this run"),
						Matchers.not(Matchers.containsString("Preparing this run")),
						Matchers.not(Matchers.containsString("hx-get=\"/reposcan/run/7/1\"")))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void aRunWhosePreparationFailedSaysThat() throws Exception {
		givenPlanWithNoScans();
		givenPreparationJob(AsyncJobStatus.FAILED);

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/run/7/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("Preparing this run failed")));
	}
}

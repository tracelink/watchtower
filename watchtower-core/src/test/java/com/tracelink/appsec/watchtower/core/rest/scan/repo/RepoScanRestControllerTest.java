package com.tracelink.appsec.watchtower.core.rest.scan.repo;

import java.util.List;
import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepoScanRestControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RepoScanService scans;

	@MockitoBean
	private RepoScanRepository rows;

	@Test
	@WithMockUser(username = "ci", authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void startsAScanAndPointsAtItsRun() throws Exception {
		RepoScanPlanEntity plan = BDDMockito.mock(RepoScanPlanEntity.class);
		BDDMockito.when(plan.getId()).thenReturn(3L);
		BDDMockito.when(scans.submit(ArgumentMatchers.any(), ArgumentMatchers.eq("ci")))
				.thenReturn(plan);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/reposcan")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"apiLabel\":\"bb\",\"repos\":[\"payments-*\"]}"))
				.andExpect(MockMvcResultMatchers.status().isAccepted())
				.andExpect(MockMvcResultMatchers.jsonPath("$.status")
						.value("/rest/reposcan/run/3/1"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void anInvalidRequestIsABadRequest() throws Exception {
		BDDMockito.when(scans.submit(ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenThrow(new IllegalArgumentException("Choose at least one repository"));

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/reposcan")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.contentType(MediaType.APPLICATION_JSON).content("{\"apiLabel\":\"bb\"}"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.jsonPath("$.error")
						.value("Choose at least one repository"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void reportsAScansStatusAndCounts() throws Exception {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRepoName("payments-api");
		RepoScanEntity scan = new RepoScanEntity();
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(ScanStatus.DONE);
		scan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH)));
		BDDMockito.when(rows.findWithRepository(5L)).thenReturn(Optional.of(scan));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/reposcan/5"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$.status").value("Done"))
				.andExpect(MockMvcResultMatchers.jsonPath("$.bySeverity.High").value(1))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.not(Matchers.containsString("reportKey"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void statusNeedsScanResults() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/rest/reposcan/5"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}
}

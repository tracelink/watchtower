package com.tracelink.appsec.watchtower.core.scan.code;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService.Kind;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;

import static org.mockito.BDDMockito.given;

@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class CodeScanResultsControllerTest {
	@Autowired MockMvc mvc;
	@MockitoBean CodeScanResultsService results;

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	void globalResultsShowTheSharedTableAndFilters() throws Exception {
		var row = new HomeActivityItem("Repository", "payments-api@main",
				StatusPresentationModel.from(ScanStatus.DONE), null, 1_000, "2.30 s", 19,
				"/reposcan/report/12");
		given(results.page(Kind.ALL, 0, null))
				.willReturn(new PagedResult<>(List.of(row), 0, 20, 1, 1));
		given(results.counts(null)).willReturn(new CodeScanResultsService.Counts(94_056, 11));
		mvc.perform(get("/scans/results"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Repository results")))
				// One tab row with counts (Fixes board): Plans and Queue are tabs, not pill buttons.
				.andExpect(content().string(containsString(">94,067<")))
				.andExpect(content().string(containsString(">94,056<")))
				.andExpect(content().string(containsString("/reposcan?view=plans")))
				.andExpect(content().string(containsString("/reposcan?view=queue")))
				.andExpect(content().string(containsString("Scanning on")))
				.andExpect(content().string(org.hamcrest.Matchers.not(containsString("btn btn-secondary btn-sm\" href=\"/reposcan?view=plans"))))
				.andExpect(content().string(containsString("/scans/results?type=pr")))
				.andExpect(content().string(containsString("/scans/results?type=repository")))
				.andExpect(content().string(containsString("payments-api@main")))
				.andExpect(content().string(containsString("Scanners")))
				.andExpect(content().string(containsString("Duration")))
				.andExpect(content().string(containsString("/reposcan/report/12")));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	void repositoryFilterUsesIndividualRepositoryScans() throws Exception {
		given(results.page(Kind.REPOSITORY, 0, null))
				.willReturn(new PagedResult<>(List.of(), 0, 20, 0, 0));
		mvc.perform(get("/scans/results?type=repository"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("No scans match this view yet.")));
	}
}

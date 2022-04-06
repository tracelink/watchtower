package com.tracelink.appsec.watchtower.core.metrics;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.util.Pair;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class MetricsDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private MetricsCacheService mockMetricsService;

	///////////////////
	// Get dashboard
	///////////////////
	@Test
	@WithMockUser
	public void testGetDashboard() throws Exception {
		long scanCount = 1;
		long violationCount = 213;
		String scanTime = "DateString";

		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(true);

		BDDMockito.when(mockMetricsService.getScanCount(BDDMockito.any())).thenReturn(scanCount);
		BDDMockito.when(mockMetricsService.getViolationCount(BDDMockito.any()))
				.thenReturn(violationCount);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any()))
				.thenReturn(scanTime);

		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				// has metrics object
				.andExpect(MockMvcResultMatchers.model().attribute("metrics", Matchers.allOf(
						// with the right keys (each scan type display name)
						// Matchers.hasKey(ScanType.PULL_REQUEST.getDisplayName()),
						// Matchers.hasKey(ScanType.UPLOAD.getDisplayName()),
						// and the scan type metrics are the correct pairs
						Matchers.hasEntry(Matchers.is(CodeScanType.PULL_REQUEST.getDisplayName()),
								Matchers.allOf(
										Matchers.hasItem(Pair.of("Scans Completed",
												String.valueOf(scanCount))),
										Matchers.hasItem(Pair.of("Violations Found",
												String.valueOf(violationCount))),
										Matchers.hasItem(Pair.of("Average Scan Time",
												scanTime)))))));
	}

	@Test
	@WithMockUser
	public void testMetricsNotReady() throws Exception {
		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(false);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any()))
				.thenReturn("");
		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						MetricsCacheService.METRICS_NOT_READY));
	}

}

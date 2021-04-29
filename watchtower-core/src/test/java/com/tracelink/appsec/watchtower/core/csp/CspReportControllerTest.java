package com.tracelink.appsec.watchtower.core.csp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class CspReportControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(CspReportController.class);

	private static final String report =
			"{\"csp-report\":{\"referrer\":\"http://localhost:8081/\",\"violated-directive\":\"script-src\",\"blocked-uri\":\"http://localhost:8081/scripts/dashboard/scans-vios-line.js\"}}";

	@Test
	public void testCspReport() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rest/csp/report").content(report)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isOk());

		Assertions.assertEquals(
				"CSP violation of script-src directive at http://localhost:8081/. Blocked URI: http://localhost:8081/scripts/dashboard/scans-vios-line.js",
				logWatcher.getMessages().get(0));
	}

	@Test
	public void testCspReportBadReport() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rest/csp/report").content("foo")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isBadRequest());
	}
}

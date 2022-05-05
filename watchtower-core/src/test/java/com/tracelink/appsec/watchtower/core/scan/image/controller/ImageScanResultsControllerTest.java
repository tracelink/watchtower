package com.tracelink.appsec.watchtower.core.scan.image.controller;

import java.util.Arrays;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultTest;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanResultsControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ImageScanResultService resultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsHome() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/results"))
				.andExpect(MockMvcResultMatchers.model().attribute("filters",
						Matchers.is(ImageResultFilter.values())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsPageSuccess() throws Exception {
		List<ImageScanResult> results = Arrays.asList(ImageScanResultTest.buildStandardResult());
		BDDMockito.when(resultService.getScanResultsWithFilters(ImageResultFilter.ALL, 10, 0))
				.thenReturn(results);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/results/all"))
				.andExpect(
						MockMvcResultMatchers.model().attribute("activeFilter", Matchers.is("all")))
				.andExpect(MockMvcResultMatchers.model().attribute("activePageNum", Matchers.is(0)))
				.andExpect(MockMvcResultMatchers.model().attribute("filters",
						Matchers.is(ImageResultFilter.values())))
				.andExpect(MockMvcResultMatchers.model().attribute("results", results));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsPageUnknownFilter() throws Exception {
		List<ImageScanResult> results = Arrays.asList(ImageScanResultTest.buildStandardResult());
		BDDMockito.when(resultService.getScanResultsWithFilters(ImageResultFilter.ALL, 10, 0))
				.thenReturn(results);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/results/foo"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, Matchers.is("Unknown Filter")))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/imagescan/results"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsPageBadPage() throws Exception {
		List<ImageScanResult> results = Arrays.asList(ImageScanResultTest.buildStandardResult());
		BDDMockito.when(resultService.getScanResultsWithFilters(ImageResultFilter.ALL, 10, 0))
				.thenReturn(results);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/results/all?page=-1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/imagescan/results/all?page=0"));
	}

}

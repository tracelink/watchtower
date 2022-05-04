package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanRestControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ImageScanningService mockImageScanningService;

	@MockBean
	private ApiIntegrationService mockApiIntegrationService;

	@Test
	@WithMockUser(authorities = {
			CorePrivilege.INTEGRATION_SCAN_SUBMIT}, username = "integrationLabel")
	public void testScanImageRequest() throws Exception {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiType()).thenReturn(ApiType.ECR);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);
		mockMvc.perform(MockMvcRequestBuilders.post("/rest/imagescan/integrationLabel")
				.content("{\"registryId\":\"123\",\"repository\":\"image\",\"tags\":[\"latest\"]}"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string("Added scan successfully"));

		ArgumentCaptor<ImageScan> imageScanCaptor = ArgumentCaptor.forClass(ImageScan.class);
		BDDMockito.verify(mockImageScanningService).doImageScan(imageScanCaptor.capture());

		ImageScan imageScan = imageScanCaptor.getValue();
		MatcherAssert.assertThat(imageScan.getRegistry(), Matchers.is("123"));
		MatcherAssert.assertThat(imageScan.getRepository(), Matchers.is("image"));
		MatcherAssert.assertThat(imageScan.getTag(), Matchers.is("latest"));
	}

	@Test
	@WithMockUser(authorities = {
			CorePrivilege.INTEGRATION_SCAN_SUBMIT}, username = "integrationLabel")
	public void testScanImageRequestNoEntity() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rest/imagescan/integrationLabel")
				.content("{\"registryId\":\"123\",\"repository\":\"image\",\"tags\":[\"latest\"]}"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.content().string("Unknown api label"));

		BDDMockito.verify(mockImageScanningService, Mockito.times(0))
				.doImageScan(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {
			CorePrivilege.INTEGRATION_SCAN_SUBMIT}, username = "integrationLabel")
	public void testScanImageRequestScanRejected() throws Exception {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiType()).thenReturn(ApiType.ECR);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);
		BDDMockito.doThrow(new ScanRejectedException("Bad scan")).when(mockImageScanningService)
				.doImageScan(BDDMockito.any(ImageScan.class));

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/imagescan/integrationLabel")
				.content("{\"registryId\":\"123\",\"repository\":\"image\",\"tags\":[\"latest\"]}"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.content().string("Bad scan"));
	}

	@Test
	@WithMockUser(authorities = {
			CorePrivilege.INTEGRATION_SCAN_SUBMIT}, username = "integrationLabel")
	public void testScanImageRequestBadParams() throws Exception {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiType()).thenReturn(ApiType.ECR);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/imagescan/integrationLabel")
				.content("{\"repository\":\"image\",\"tags\":[\"latest\"]}"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.content()
						.string("Error adding the scan: Required params are 'registryId', 'repository', and a nonempty 'tags' array"));

		BDDMockito.verify(mockImageScanningService, Mockito.times(0)).doImageScan(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {
			CorePrivilege.INTEGRATION_SCAN_SUBMIT}, username = "integrationLabel")
	public void testScanImageRequestBadApiType() throws Exception {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		ApiType mockApiType = BDDMockito.mock(ApiType.class);
		BDDMockito.when(integrationEntity.getApiType()).thenReturn(mockApiType);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/imagescan/integrationLabel")
				.content("{\"repository\":\"image\",\"tags\":[\"latest\"]}"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.content()
						.string("Error adding the scan: No image API for this label."));

		BDDMockito.verify(mockImageScanningService, Mockito.times(0)).doImageScan(BDDMockito.any());
	}

}


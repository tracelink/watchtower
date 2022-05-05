package com.tracelink.appsec.watchtower.core.rest.scan.upload;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Random;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UploadScanRestControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UploadScanningService mockUploadScanningService;

	@MockBean
	private UploadScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testScanUpload() throws Exception {
		String name = "uploadFile";
		String originalFilename = "originalFilename.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);
		MockMultipartFile file = new MockMultipartFile(name, originalFilename, "zip", content);

		String ticket = "ticket";

		BDDMockito.when(mockUploadScanningService.copyToLocation(file))
				.thenReturn(Paths.get("some"));
		BDDMockito.when(mockUploadScanningService.doUploadScan(BDDMockito.any()))
				.thenReturn(ticket);
		BDDMockito.when(mockScanResultService.generateResultForTicket(ticket))
				.thenReturn(new UploadScanResult());

		mockMvc.perform(MockMvcRequestBuilders.multipart("/rest/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockUploadScanningService).doUploadScan(BDDMockito.any());
		BDDMockito.verify(mockScanResultService).generateResultForTicket(ticket);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testScanUploadRejected() throws Exception {
		String name = "uploadFile";
		String originalFilename = "originalFilename.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);
		MockMultipartFile file = new MockMultipartFile(name, originalFilename, "zip", content);

		String message = "message";

		BDDMockito.when(mockUploadScanningService.copyToLocation(file))
				.thenReturn(Paths.get("some"));
		BDDMockito.when(mockUploadScanningService.doUploadScan(BDDMockito.any()))
				.thenThrow(new ScanRejectedException(message));
		mockMvc.perform(MockMvcRequestBuilders.multipart("/rest/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()));

		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockScanResultService).generateFailedUploadResult(BDDMockito.any(),
				captor.capture());
		Assertions.assertEquals(message, captor.getValue());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testScanUploadBadCopy() throws Exception {
		String name = "uploadFile";
		String originalFilename = "originalFilename.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);
		MockMultipartFile file = new MockMultipartFile(name, originalFilename, "zip", content);

		String message = "message";

		BDDMockito.when(mockUploadScanningService.copyToLocation(file))
				.thenThrow(new IOException(message));
		mockMvc.perform(MockMvcRequestBuilders.multipart("/rest/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()));

		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockScanResultService).generateFailedUploadResult(BDDMockito.any(),
				captor.capture());
		MatcherAssert.assertThat(captor.getValue(), Matchers.containsString(message));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testGetResultForTicket() throws Exception {
		String ticket = "ticket";

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/uploadscan/" + ticket));

		BDDMockito.verify(mockScanResultService).generateResultForTicket(ticket);
	}
}

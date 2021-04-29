package com.tracelink.appsec.watchtower.core.scan.upload.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanningService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UploadScanControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UploadScanningService mockScanService;

	@MockBean
	private UploadScanResultService mockScanResultService;

	@MockBean
	private RulesetService mockRulesetService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScan() throws Exception {
		long queued = 1L;
		long progress = 0L;
		boolean paused = false;
		boolean quiesced = false;
		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getName()).thenReturn("");
		UploadScanEntity lastScan = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(lastScan.getContainer()).thenReturn(container);
		BDDMockito.when(lastScan.getStatus()).thenReturn(ScanStatus.DONE);
		RulesetDto ruleset = BDDMockito.mock(RulesetDto.class);
		BDDMockito.when(ruleset.getName()).thenReturn("");
		RulesetEntity defaultRuleset = BDDMockito.mock(RulesetEntity.class);
		BDDMockito.when(defaultRuleset.getName()).thenReturn("");

		BDDMockito.when(mockScanService.getTaskNumInQueue()).thenReturn(queued);
		BDDMockito.when(mockScanService.getTaskNumActive()).thenReturn(progress);
		BDDMockito.when(mockScanService.isPaused()).thenReturn(paused);
		BDDMockito.when(mockScanService.isQuiesced()).thenReturn(quiesced);
		BDDMockito.when(mockScanResultService.getLastScans(BDDMockito.anyInt()))
				.thenReturn(Arrays.asList(lastScan));
		BDDMockito.when(mockRulesetService.getRulesets()).thenReturn(Arrays.asList(ruleset));
		BDDMockito.when(mockRulesetService.getDefaultRuleset()).thenReturn(defaultRuleset);

		mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan"))
				.andExpect(MockMvcResultMatchers.model().attribute("numScansQueued", queued))
				.andExpect(MockMvcResultMatchers.model().attribute("numScansInProgress", progress))
				.andExpect(MockMvcResultMatchers.model().attribute("scanStatePaused", paused))
				.andExpect(MockMvcResultMatchers.model().attribute("scanStateQuiesced", quiesced))
				.andExpect(MockMvcResultMatchers.model().attribute("lastScans",
						Matchers.contains(lastScan)))
				.andExpect(MockMvcResultMatchers.model().attribute("rulesets",
						Matchers.contains(ruleset)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("defaultRuleset", defaultRuleset));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testSubmitScan() throws Exception {
		String originalFileName = "original.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);

		Path zipPath = Files.createTempFile(null, "zip");
		String ticket = "ticket";
		BDDMockito.when(mockScanService.copyToLocation(BDDMockito.any())).thenReturn(zipPath);
		BDDMockito.when(mockScanService.doUploadScan(BDDMockito.any())).thenReturn(ticket);
		MockMultipartFile file =
				new MockMultipartFile("uploadFile", originalFileName, null, content);
		mockMvc.perform(MockMvcRequestBuilders.multipart("/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString(ticket)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testSubmitScanCopyError() throws Exception {
		String originalFileName = "original.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);
		String message = "message";
		BDDMockito.when(mockScanService.copyToLocation(BDDMockito.any()))
				.thenThrow(new IOException(message));
		MockMultipartFile file =
				new MockMultipartFile("uploadFile", originalFileName, null, content);
		mockMvc.perform(MockMvcRequestBuilders.multipart("/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.allOf(Matchers.containsString(message),
								Matchers.containsString("Error copying"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME}, username = "user")
	public void testSubmitScanRejectionError() throws Exception {
		String originalFileName = "original.zip";
		byte[] content = new byte[512];
		new Random().nextBytes(content);
		String message = "message";
		Path zipPath = Files.createTempFile(null, "zip");
		BDDMockito.when(mockScanService.copyToLocation(BDDMockito.any())).thenReturn(zipPath);
		BDDMockito.when(mockScanService.doUploadScan(BDDMockito.any()))
				.thenThrow(new ScanRejectedException(message));
		MockMultipartFile file =
				new MockMultipartFile("uploadFile", originalFileName, null, content);
		mockMvc.perform(MockMvcRequestBuilders.multipart("/uploadscan").file(file)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString(message)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testPauseUnpause() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/uploadscan/pause")
				.param("pause", "true")
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(mockScanService).pauseExecution();
		BDDMockito.verify(mockScanService, BDDMockito.never()).resumeExecution();

		mockMvc.perform(MockMvcRequestBuilders.post("/uploadscan/pause")
				.param("pause", "false")
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(mockScanService).pauseExecution();
		BDDMockito.verify(mockScanService).resumeExecution();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testQuiesceUnquiesce() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/uploadscan/quiesce")
				.param("quiesce", "true")
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(mockScanService).quiesce();
		BDDMockito.verify(mockScanService, BDDMockito.never()).unQuiesce();

		mockMvc.perform(MockMvcRequestBuilders.post("/uploadscan/quiesce")
				.param("quiesce", "false")
				.with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(mockScanService).quiesce();
		BDDMockito.verify(mockScanService).unQuiesce();
	}
}

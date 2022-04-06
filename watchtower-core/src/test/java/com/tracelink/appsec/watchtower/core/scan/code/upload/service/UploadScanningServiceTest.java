package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.multipart.MultipartFile;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class UploadScanningServiceTest {

	@MockBean
	private LogsService mockLogService;

	@MockBean
	private RulesetService mockRulesetService;

	@MockBean
	private ScanRegistrationService mockScanRegistrationService;

	@MockBean
	private UploadScanResultService mockUploadScanResultService;

	private UploadScanningService scanningService;

	@BeforeEach
	public void setup() {
		this.scanningService = new UploadScanningService(mockLogService, mockRulesetService,
				mockScanRegistrationService, mockUploadScanResultService, 2, false);
	}

	@Test
	public void testDoUploadScan() throws Exception {
		String name = "name";
		String rulesetName = "ruleset";
		String ticket = "ticket";
		Path filePath = Paths.get("something");

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setFilePath(filePath);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setZipPath(filePath);

		RulesetEntity ruleset = BDDMockito.mock(RulesetEntity.class);
		BDDMockito.when(ruleset.getName()).thenReturn(rulesetName);

		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString())).thenReturn(ruleset);
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.INFO);
		BDDMockito.when(
				mockUploadScanResultService.makeNewScanEntity(BDDMockito.any(UploadScan.class)))
				.thenReturn(container);

		String ticketReturn = scanningService.doUploadScan(scan);

		Assertions.assertEquals(ticket, ticketReturn);
	}

	@Test
	public void testDoUploadScanQuiesced() throws Exception {
		String name = "name";
		UploadScan scan = new UploadScan();
		scan.setName(name);
		this.scanningService.quiesce();

		try {
			scanningService.doUploadScan(scan);
			Assertions.fail("Should have thrown exception");
		} catch (ScanRejectedException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Quiesced"));
		}
	}

	@Test
	public void testDoUploadScanNoRulesetGiven() throws Exception {
		String name = "name";
		String rulesetName = "ruleset";
		String ticket = "ticket";
		Path filePath = Paths.get("something");

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setFilePath(filePath);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setZipPath(filePath);

		RulesetEntity ruleset = BDDMockito.mock(RulesetEntity.class);
		BDDMockito.when(ruleset.getName()).thenReturn(rulesetName);

		BDDMockito.when(mockRulesetService.getDefaultRuleset()).thenReturn(ruleset);
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.INFO);
		BDDMockito.when(
				mockUploadScanResultService.makeNewScanEntity(BDDMockito.any(UploadScan.class)))
				.thenReturn(container);

		String ticketReturn = scanningService.doUploadScan(scan);

		Assertions.assertEquals(ticket, ticketReturn);
	}

	@Test
	public void testDoUploadScanBadRuleset() throws Exception {
		String name = "name";
		String rulesetName = "ruleset";
		String ticket = "ticket";
		Path filePath = Paths.get("something");

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setFilePath(filePath);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setZipPath(filePath);


		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
				.thenThrow(RulesetNotFoundException.class);

		try {
			scanningService.doUploadScan(scan);
			Assertions.fail("Should throw exception");
		} catch (ScanRejectedException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Unknown Ruleset"));
		}
	}

	@Test
	public void testDoUploadScanNoScanners() throws Exception {
		String name = "name";
		String rulesetName = "ruleset";
		String ticket = "ticket";
		Path filePath = Paths.get("something");

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setFilePath(filePath);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setZipPath(filePath);

		RulesetEntity ruleset = BDDMockito.mock(RulesetEntity.class);
		BDDMockito.when(ruleset.getName()).thenReturn(rulesetName);

		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString())).thenReturn(ruleset);
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(false);
		try {
			scanningService.doUploadScan(scan);
			Assertions.fail("Should throw exception");
		} catch (ScanRejectedException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("no scanners configured"));
		}
	}

	@Test
	public void testCopyMultipart() throws Exception {
		Path zipLocation = null;
		try {
			byte[] content = new byte[512];
			new Random().nextBytes(content);

			MultipartFile file = BDDMockito.mock(MultipartFile.class);
			BDDMockito.when(file.getInputStream()).thenReturn(new ByteArrayInputStream(content));
			zipLocation = scanningService.copyToLocation(file);
			Assertions.assertArrayEquals(content, Files.readAllBytes(zipLocation));
		} finally {
			Files.deleteIfExists(zipLocation);
		}
	}

	@Test
	public void testRecoverFromDowntimeSuccess() throws Exception {
		Path file1 = null;
		Path file2 = null;
		try {
			file1 = Files.createTempFile(null, null);
			file1.toFile().createNewFile();
			file2 = Files.createTempFile(null, null);
			file2.toFile().createNewFile();
			UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
			BDDMockito.when(container1.getZipPath()).thenReturn(file1);
			BDDMockito.when(container1.getRuleSet()).thenReturn("foo");

			UploadScanContainerEntity container2 = BDDMockito.mock(UploadScanContainerEntity.class);
			BDDMockito.when(container2.getZipPath()).thenReturn(file2);
			BDDMockito.when(container2.getRuleSet()).thenReturn("foo");

			BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS))
					.thenReturn(Arrays.asList(container1));
			BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
					.thenReturn(Arrays.asList(container2));
			BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
					.thenReturn(BDDMockito.mock(RulesetEntity.class));
			BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.DEBUG);

			scanningService.recoverFromDowntime();
			// testing the agent code is called
			BDDMockito.verify(mockScanRegistrationService, BDDMockito.times(2)).getCodeScanners();
			Assertions.assertFalse(file1.toFile().exists());
			Assertions.assertFalse(file2.toFile().exists());
		} finally {
			Files.deleteIfExists(file1);
			Files.deleteIfExists(file2);
		}
	}

	@Test
	public void testRecoverFromDowntimeBadRuleset() throws Exception {
		Path file1 = null;
		try {
			file1 = Files.createTempFile(null, null);
			file1.toFile().createNewFile();

			UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
			BDDMockito.when(container1.getZipPath()).thenReturn(file1);
			BDDMockito.when(container1.getRuleSet()).thenReturn("foo");
			BDDMockito.when(container1.getTicket()).thenReturn("ticket");

			BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS))
					.thenReturn(Arrays.asList(container1));
			BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
					.thenThrow(RulesetNotFoundException.class);

			scanningService.recoverFromDowntime();
			// testing the agent code is called
			ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
			BDDMockito.verify(mockUploadScanResultService, BDDMockito.times(1))
					.markScanFailed(BDDMockito.anyString(), reasonCaptor.capture());
			MatcherAssert.assertThat(reasonCaptor.getValue(),
					Matchers.containsString("ruleset is invalid"));
			Assertions.assertFalse(file1.toFile().exists());
		} finally {
			Files.deleteIfExists(file1);
		}
	}

	@Test
	public void testRecoverFromDowntimeNoZip() throws Exception {
		Path file1 = Paths.get("foo");

		UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container1.getZipPath()).thenReturn(file1);
		BDDMockito.when(container1.getRuleSet()).thenReturn("foo");
		BDDMockito.when(container1.getTicket()).thenReturn("ticket");

		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
				.thenReturn(Arrays.asList(container1));

		scanningService.recoverFromDowntime();
		// testing the agent code is called
		ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockUploadScanResultService, BDDMockito.times(1))
				.markScanFailed(BDDMockito.anyString(), reasonCaptor.capture());
		MatcherAssert.assertThat(reasonCaptor.getValue(),
				Matchers.containsString("no longer exists"));
	}
}

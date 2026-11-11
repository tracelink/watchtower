package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import ch.qos.logback.classic.Level;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadStorageLocation;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.multipart.MultipartFile;

@ExtendWith(SpringExtension.class)
public class UploadScanningServiceTest {

	@MockitoBean
	private LogsService mockLogService;

	@MockitoBean
	private RulesetService mockRulesetService;

	@MockitoBean
	private ScanRegistrationService mockScanRegistrationService;

	@MockitoBean
	private UploadScanResultService mockUploadScanResultService;

	@MockitoBean
	private S3Service mockS3Service;

	private UploadScanningService scanningService;
	private SimpleMeterRegistry meterRegistry;

	@BeforeEach
	public void setup() {
		this.meterRegistry = new SimpleMeterRegistry();
		this.scanningService = new UploadScanningService(mockLogService, mockRulesetService,
				mockScanRegistrationService, mockUploadScanResultService, mockS3Service,
				meterRegistry, 2, false);
		// Paused by default and never resumed in this test class: no test here asserts
		// on a queued UploadScanAgent actually completing, only on the synchronous
		// side effects of submitting it (ticket return, counters, mock call counts).
		// A real agent run against a placeholder zip fails to unzip it and calls
		// markScanFailed() on the shared @MockitoBean at an unpredictable later point,
		// intermittently failing whichever test happens to be running when it lands.
		this.scanningService.pauseExecution();
	}

	@Test
	public void testDoUploadScan() throws Exception {
		String name = "name";
		String rulesetName = "ruleset";
		String ticket = "ticket";
		String s3Key = "uploads/something.zip";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setStorageKey(s3Key);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setStorageKey(s3Key);

		RulesetEntity ruleset = BDDMockito.mock(RulesetEntity.class);
		BDDMockito.when(ruleset.getName()).thenReturn(rulesetName);

		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString())).thenReturn(ruleset);
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.INFO);
		BDDMockito.when(
				mockUploadScanResultService.makeNewScanEntity(BDDMockito.any(UploadScan.class)))
				.thenReturn(container);

		double before = meterRegistry.get("watchtower.scan.queued").tag("type", "upload")
				.counter().count();
		String ticketReturn = scanningService.doUploadScan(scan);
		double after = meterRegistry.get("watchtower.scan.queued").tag("type", "upload")
				.counter().count();

		Assertions.assertEquals(ticket, ticketReturn);
		// IMPROVEMENT_PLAN.md item 6.6 smoke test: a queued scan bumps
		// watchtower.scan.queued{type=upload}.
		Assertions.assertEquals(before + 1, after);
	}

	@Test
	public void testQueueDepthGaugeIsRegistered() {
		// IMPROVEMENT_PLAN.md item 6.6: watchtower.scan.queue.depth{type=upload} must be
		// present in /actuator/metrics even before any scan is queued.
		Assertions.assertEquals(0.0,
				meterRegistry.get("watchtower.scan.queue.depth").tag("type", "upload").gauge()
						.value());
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
		String s3Key = "uploads/something.zip";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setStorageKey(s3Key);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setStorageKey(s3Key);

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
		String s3Key = "uploads/something.zip";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setStorageKey(s3Key);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setStorageKey(s3Key);

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
		String s3Key = "uploads/something.zip";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(rulesetName);
		scan.setStorageKey(s3Key);

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setTicket(ticket);
		container.setStorageKey(s3Key);

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
	public void testCopyMultipartUploadsToS3WhenEnabled() throws Exception {
		byte[] content = new byte[512];
		new Random().nextBytes(content);

		MultipartFile file = BDDMockito.mock(MultipartFile.class);
		BDDMockito.when(file.getInputStream()).thenReturn(new ByteArrayInputStream(content));
		BDDMockito.when(file.getSize()).thenReturn((long) content.length);
		BDDMockito.when(mockS3Service.isEnabled()).thenReturn(true);

		String storageKey = scanningService.storeUpload(file);

		Assertions.assertTrue(UploadStorageLocation.isS3(storageKey));
		String s3Key = UploadStorageLocation.s3Key(storageKey);
		MatcherAssert.assertThat(s3Key, Matchers.startsWith("uploads/"));
		BDDMockito.verify(mockS3Service).uploadRequired(BDDMockito.eq(s3Key),
				BDDMockito.any(), BDDMockito.eq((long) content.length));
	}

	@Test
	public void testCopyMultipartPropagatesS3Failure() throws Exception {
		MultipartFile file = BDDMockito.mock(MultipartFile.class);
		BDDMockito.when(file.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
		BDDMockito.when(mockS3Service.isEnabled()).thenReturn(true);
		BDDMockito.doThrow(new IOException("boom")).when(mockS3Service)
				.uploadRequired(BDDMockito.anyString(), BDDMockito.any(), BDDMockito.anyLong());

		try {
			scanningService.storeUpload(file);
			Assertions.fail("Should have thrown IOException");
		} catch (IOException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("boom"));
		}
	}

	@Test
	public void testCopyMultipartFallsBackToLocalDiskWhenS3Disabled() throws Exception {
		byte[] content = new byte[512];
		new Random().nextBytes(content);

		MultipartFile file = BDDMockito.mock(MultipartFile.class);
		BDDMockito.when(file.getInputStream()).thenReturn(new ByteArrayInputStream(content));
		// mockS3Service.isEnabled() defaults to false - S3 is "not configured".

		String storageKey = scanningService.storeUpload(file);
		try {
			Assertions.assertFalse(UploadStorageLocation.isS3(storageKey));
			Path localPath = UploadStorageLocation.localPath(storageKey);
			Assertions.assertArrayEquals(content, Files.readAllBytes(localPath));
			BDDMockito.verify(mockS3Service, BDDMockito.never()).uploadRequired(
					BDDMockito.anyString(), BDDMockito.any(), BDDMockito.anyLong());
		} finally {
			Files.deleteIfExists(UploadStorageLocation.localPath(storageKey));
		}
	}

	@Test
	public void testRecoverFromDowntimeSuccess() throws Exception {
		String key1 = "uploads/one.zip";
		String key2 = "uploads/two.zip";
		BDDMockito.when(mockS3Service.keyExists(key1)).thenReturn(true);
		BDDMockito.when(mockS3Service.keyExists(key2)).thenReturn(true);

		UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container1.getStorageKey()).thenReturn(UploadStorageLocation.forS3Key(key1));
		BDDMockito.when(container1.getRuleSet()).thenReturn("foo");

		UploadScanContainerEntity container2 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container2.getStorageKey()).thenReturn(UploadStorageLocation.forS3Key(key2));
		BDDMockito.when(container2.getRuleSet()).thenReturn("foo");

		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS))
				.thenReturn(Arrays.asList(container1));
		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
				.thenReturn(Arrays.asList(container2));
		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(RulesetEntity.class));
		BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.DEBUG);

		// Paused, and deliberately never resumed. getCodeScanners() is called
		// synchronously inside submitScan() before the agent is ever handed to the
		// executor, so pausing doesn't affect this test's assertion - but leaving the
		// executor running let the queued agent actually execute in the background
		// against an empty placeholder zip, fail to unzip it, and call
		// markScanFailed() on the shared @MockitoBean at an unpredictable later point,
		// intermittently failing whichever test happened to be running when it landed.
		scanningService.pauseExecution();
		scanningService.recoverFromDowntime();
		// testing the agent code is called
		BDDMockito.verify(mockScanRegistrationService, BDDMockito.times(2)).getCodeScanners();
	}

	@Test
	public void testRecoverFromDowntimeKeepsZipForTheQueuedScan() throws Exception {
		String key = "uploads/one.zip";
		BDDMockito.when(mockS3Service.keyExists(key)).thenReturn(true);

		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getStorageKey()).thenReturn(UploadStorageLocation.forS3Key(key));
		BDDMockito.when(container.getRuleSet()).thenReturn("foo");

		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS))
				.thenReturn(Arrays.asList(container));
		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
				.thenReturn(Collections.emptyList());
		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(RulesetEntity.class));
		BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.DEBUG);

		// Pause the executor so the queued agent cannot run, and deliberately never
		// resume it: this scanningService instance is scoped to this test only, and
		// resuming would let the queued agent run on a background thread against an
		// empty placeholder zip, fail, and call markScanFailed() on the shared
		// @MockitoBean after this test method has already returned - the same
		// contamination this test exists to guard against, just moved to a later test.
		scanningService.pauseExecution();
		scanningService.recoverFromDowntime();

		// The whole point of recovery is to rescan this upload, so its object must
		// not be deleted here.
		BDDMockito.verify(mockS3Service, BDDMockito.never()).deleteObject(key);
		BDDMockito.verify(mockUploadScanResultService, BDDMockito.never())
				.markScanFailed(BDDMockito.anyString(), BDDMockito.anyString());
	}

	@Test
	public void testRecoverFromDowntimeBadRuleset() throws Exception {
		String key = "uploads/one.zip";
		BDDMockito.when(mockS3Service.keyExists(key)).thenReturn(true);

		UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container1.getStorageKey()).thenReturn(UploadStorageLocation.forS3Key(key));
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
		BDDMockito.verify(mockS3Service).deleteObject(key);
	}

	@Test
	public void testRecoverFromDowntimeNoZip() throws Exception {
		String key = "uploads/missing.zip";
		BDDMockito.when(mockS3Service.keyExists(key)).thenReturn(false);

		UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container1.getStorageKey()).thenReturn(UploadStorageLocation.forS3Key(key));
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

	@Test
	public void testRecoverFromDowntimeLocalBackedScanChecksFileExistence() throws Exception {
		Path localZip = Files.createTempFile(null, null);
		try {
			String storageKey = UploadStorageLocation.forLocalPath(localZip);

			UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
			BDDMockito.when(container.getStorageKey()).thenReturn(storageKey);
			BDDMockito.when(container.getRuleSet()).thenReturn("foo");

			BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS))
					.thenReturn(Arrays.asList(container));
			BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
					.thenReturn(Collections.emptyList());
			BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyString()))
					.thenReturn(BDDMockito.mock(RulesetEntity.class));
			BDDMockito.when(mockLogService.getLogsLevel()).thenReturn(Level.DEBUG);

			// Paused, and deliberately never resumed: this scanningService instance is
			// scoped to this test only, so leaving it paused (rather than calling
			// resumeExecution()) is what keeps the queued agent from ever running on a
			// background thread after localZip is deleted below - the same
			// shared-@MockitoBean race documented on
			// testRecoverFromDowntimeSuccess above, avoided here by construction instead
			// of by a comment.
			scanningService.pauseExecution();
			scanningService.recoverFromDowntime();

			BDDMockito.verifyNoInteractions(mockS3Service);
			BDDMockito.verify(mockUploadScanResultService, BDDMockito.never())
					.markScanFailed(BDDMockito.anyString(), BDDMockito.anyString());
		} finally {
			Files.deleteIfExists(localZip);
		}
	}

	@Test
	public void testRecoverFromDowntimeLocalBackedScanMissingFileMarksFailed() throws Exception {
		String storageKey =
				UploadStorageLocation.forLocalPath(Path.of("/nonexistent/path/to/upload.zip"));

		UploadScanContainerEntity container1 = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container1.getStorageKey()).thenReturn(storageKey);
		BDDMockito.when(container1.getRuleSet()).thenReturn("foo");
		BDDMockito.when(container1.getTicket()).thenReturn("ticket");

		BDDMockito.when(mockUploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED))
				.thenReturn(Arrays.asList(container1));

		scanningService.recoverFromDowntime();

		ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockUploadScanResultService, BDDMockito.times(1))
				.markScanFailed(BDDMockito.anyString(), reasonCaptor.capture());
		MatcherAssert.assertThat(reasonCaptor.getValue(),
				Matchers.containsString("no longer exists"));
		BDDMockito.verifyNoInteractions(mockS3Service);
	}
}

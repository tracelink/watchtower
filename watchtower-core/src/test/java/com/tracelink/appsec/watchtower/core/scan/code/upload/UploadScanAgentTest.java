package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

@ExtendWith(MockitoExtension.class)
public class UploadScanAgentTest {

	@Mock
	private UploadScanResultService mockScanResultService;

	@Mock
	private ICodeScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	@Mock
	private S3Service mockS3Service;

	private UploadScanContainerEntity makeContainer(String name, String ticket, String s3Key) {
		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getName()).thenReturn(name);
		BDDMockito.when(container.getTicket()).thenReturn(ticket);
		BDDMockito.when(container.getStorageKey()).thenReturn(s3Key);
		return container;
	}

	/**
	 * Stubs {@link S3Service#downloadRequired(String, Path)} to copy a local test-fixture
	 * zip in place of an actual S3 download, mirroring what {@link UploadScanAgent}
	 * expects the real service to do.
	 */
	private void stubDownload(String key, Path sourceZip) throws IOException {
		BDDMockito.willAnswer(invocation -> {
			Path target = invocation.getArgument(1);
			Files.copy(sourceZip, target, StandardCopyOption.REPLACE_EXISTING);
			return null;
		}).given(mockS3Service).downloadRequired(BDDMockito.eq(key), BDDMockito.any(Path.class));
	}

	@Test
	public void testInitializeException() {
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", "some-key"))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1);
		try {
			agent.initialize();
			Assertions.fail("Exception should have been thrown");
		} catch (ScanInitializationException e) {
			// correct
		}
	}

	@Test
	public void testInitializeBadZip() throws URISyntaxException, IOException {
		Path zip = Files.createTempFile(null, ".zip");
		String key = "some-key";
		String storageKey = UploadStorageLocation.forS3Key(key);

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/illegalZipFile.zip"),
					fos);
		}
		stubDownload(key, zip);

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", storageKey))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService)
						.withS3Service(mockS3Service);
		try {
			agent.initialize();
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Failed to unzip"));
		} finally {
			agent.clean();
		}
	}

	@Test
	public void testInitializeGoodZip()
			throws URISyntaxException, IOException, ScanInitializationException {
		Path zip = Files.createTempFile(null, ".zip");
		String key = "some-key";
		String storageKey = UploadStorageLocation.forS3Key(key);

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/legalZipFile.zip"),
					fos);
		}
		stubDownload(key, zip);

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", storageKey))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService)
						.withS3Service(mockS3Service);
		try {
			agent.initialize();
		} finally {
			agent.clean();
		}
		// S3-backed: clean() must remove both the local temp download and the S3
		// object itself.
		BDDMockito.verify(mockS3Service).deleteObject(key);
	}

	@Test
	public void testInitializeLocalFallbackUnzipsDirectlyWithoutS3Service()
			throws URISyntaxException, IOException, ScanInitializationException {
		Path zip = Files.createTempFile(null, ".zip");
		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/legalZipFile.zip"),
					fos);
		}
		String storageKey = UploadStorageLocation.forLocalPath(zip);

		// No withS3Service() call: a locally-backed upload must never touch it.
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", storageKey))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);
		try {
			agent.initialize();
		} finally {
			agent.clean();
		}

		Assertions.assertFalse(zip.toFile().exists(),
				"clean() must delete the local upload file, matching pre-S3 behavior");
	}

	@Test
	public void testInitializeLocalFallbackCleanNeverCallsS3ServiceWhenConfigured()
			throws URISyntaxException, IOException, ScanInitializationException {
		Path zip = Files.createTempFile(null, ".zip");
		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/legalZipFile.zip"),
					fos);
		}
		String storageKey = UploadStorageLocation.forLocalPath(zip);

		// A locally-backed upload's clean() must not call S3Service even when one is
		// configured on the agent - a stray deleteObject() on a local path string would
		// be a silent no-op today and a real deletion the moment the key scheme changes.
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", storageKey))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService)
						.withS3Service(mockS3Service);
		try {
			agent.initialize();
		} finally {
			agent.clean();
		}

		BDDMockito.verifyNoInteractions(mockS3Service);
	}

	@Test
	public void testInitializeBinaryFiles()
			throws URISyntaxException, IOException, ScanInitializationException {
		Path zip = Files.createTempFile(null, ".zip");
		String key = "some-key";
		String storageKey = UploadStorageLocation.forS3Key(key);

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/binaryfile.zip"),
					fos);
		}
		stubDownload(key, zip);

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", storageKey))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService)
						.withS3Service(mockS3Service);
		try {
			agent.initialize();
			Assertions.assertEquals(0, Files.list(agent.getWorkingDirectory()).count());
		} finally {
			agent.clean();
		}
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testReport() {
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", "something"))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);

		String file = "file";
		Path filePath = agent.getWorkingDirectory().resolve(file);

		int lineNum = 1;
		RulePriority sev = RulePriority.HIGH;
		String message = "message";

		CodeScanViolation sv = new CodeScanViolation();
		sv.setFileName(filePath.toString());
		sv.setLineNum(lineNum);
		sv.setSeverity(sev);
		sv.setMessage(message);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);

		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(sv));

		agent.report(Arrays.asList(report));

		ArgumentCaptor<List<UploadViolationEntity>> listCaptor =
				ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(mockScanResultService).saveFinalUploadScan(BDDMockito.anyString(),
				listCaptor.capture(), BDDMockito.any(com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.class));
		List<UploadViolationEntity> vioList = listCaptor.getValue();
		Assertions.assertEquals(1, vioList.size());
		Assertions.assertEquals(sev, vioList.get(0).getSeverity());
	}

	@Test
	public void testHandeScanException() {
		String ticket = "ticket";
		String exceptionMessage = "foobar";
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", ticket, "something"))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);

		agent.handleScanException(new Exception(exceptionMessage));
		BDDMockito.verify(mockScanResultService).markScanFailed(ticket, exceptionMessage);
	}
}

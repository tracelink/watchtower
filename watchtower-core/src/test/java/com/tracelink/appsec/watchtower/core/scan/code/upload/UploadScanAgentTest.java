package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

@ExtendWith(MockitoExtension.class)
public class UploadScanAgentTest {

	@Mock
	private UploadScanResultService mockScanResultService;

	@Mock
	private IScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	private UploadScanContainerEntity makeContainer(String name, String ticket, Path zipPath) {
		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getName()).thenReturn(name);
		BDDMockito.when(container.getTicket()).thenReturn(ticket);
		BDDMockito.when(container.getZipPath()).thenReturn(zipPath);
		return container;
	}

	@Test
	public void testInitializeException() {
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", Paths.get("something")))
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

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/illegalZipFile.zip"),
					fos);
		}

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", zip))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);
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

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/legalZipFile.zip"),
					fos);
		}

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", zip))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);
		try {
			agent.initialize();
		} finally {
			agent.clean();
		}
	}

	@Test
	public void testInitializeBinaryFiles()
			throws URISyntaxException, IOException, ScanInitializationException {
		Path zip = Files.createTempFile(null, ".zip");

		try (FileOutputStream fos = new FileOutputStream(zip.toFile())) {
			IOUtils.copy(
					UploadScanAgent.class.getResourceAsStream("/zipuploadfiles/binaryfile.zip"),
					fos);
		}

		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", "ticket", zip))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);
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
				new UploadScanAgent(makeContainer("name", "ticket", Paths.get("something")))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);

		String file = "file";
		Path filePath = agent.getWorkingDirectory().resolve(file);

		int lineNum = 1;
		String sev = "severity";
		int sevNum = 5;
		String message = "message";

		ScanViolation sv = new ScanViolation();
		sv.setFileName(filePath.toString());
		sv.setLineNum(lineNum);
		sv.setSeverity(sev);
		sv.setSeverityValue(sevNum);
		sv.setMessage(message);

		ScanReport report = BDDMockito.mock(ScanReport.class);

		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(sv));

		agent.report(Arrays.asList(report));

		ArgumentCaptor<List<UploadViolationEntity>> listCaptor =
				ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(mockScanResultService).saveFinalUploadScan(BDDMockito.anyString(),
				listCaptor.capture());
		List<UploadViolationEntity> vioList = listCaptor.getValue();
		Assertions.assertEquals(1, vioList.size());
		Assertions.assertEquals(sev, vioList.get(0).getSeverity());
	}

	@Test
	public void testHandeScanException() {
		String ticket = "ticket";
		String exceptionMessage = "foobar";
		UploadScanAgent agent =
				new UploadScanAgent(makeContainer("name", ticket, Paths.get("something")))
						.withScanners(Collections.singleton(mockScanner))
						.withRuleset(mockRuleset)
						.withThreads(1)
						.withScanResultService(mockScanResultService);

		agent.handleScanException(new Exception(exceptionMessage));
		BDDMockito.verify(mockScanResultService).markScanFailed(ticket, exceptionMessage);
	}
}

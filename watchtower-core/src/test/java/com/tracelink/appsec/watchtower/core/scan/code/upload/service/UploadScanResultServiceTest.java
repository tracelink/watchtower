package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResultViolation;


@ExtendWith(SpringExtension.class)
public class UploadScanResultServiceTest {

	@MockBean
	private UploadContainerRepository mockUploadRepo;

	@MockBean
	private UploadScanRepository mockScanRepo;

	@MockBean
	private UploadViolationRepository mockVioRepo;

	@MockBean
	private RuleService mockRuleService;

	private UploadScanResultService scanResultService;

	@BeforeEach
	public void setup() {
		this.scanResultService =
				new UploadScanResultService(mockUploadRepo, mockScanRepo, mockVioRepo,
						mockRuleService);
	}

	@Test
	public void testMakeNewScanEntity() {
		// test that the UUID check works. first time finds an entity, second doesn't.
		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString()))
				.thenReturn(new UploadScanContainerEntity()).thenReturn(null);

		String name = "name";
		String ruleSet = "ruleSet";
		Path filePath = Paths.get("some", "path");
		String user = "user";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(ruleSet);
		scan.setFilePath(filePath);
		scan.setUser(user);

		BDDMockito.when(mockUploadRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(invoke -> invoke.getArgument(0));

		UploadScanContainerEntity entity = scanResultService.makeNewScanEntity(scan);

		ArgumentCaptor<UploadScanEntity> scanEntityCaptor =
				ArgumentCaptor.forClass(UploadScanEntity.class);
		BDDMockito.verify(mockScanRepo).saveAndFlush(scanEntityCaptor.capture());

		ArgumentCaptor<String> ticketCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockUploadRepo, BDDMockito.times(2)).findByTicket(ticketCaptor.capture());

		Assertions.assertEquals(2, ticketCaptor.getAllValues().size());
		Assertions.assertNotEquals(ticketCaptor.getAllValues().get(0),
				ticketCaptor.getAllValues().get(1));

		Assertions.assertEquals(name, entity.getName());
		Assertions.assertEquals(ruleSet, entity.getRuleSet());
		Assertions.assertEquals(filePath.toAbsolutePath(), entity.getZipPath());
		Assertions.assertEquals(user, entity.getSubmitter());
		Assertions.assertEquals(ticketCaptor.getValue(), entity.getTicket());

		Assertions.assertEquals(entity, scanEntityCaptor.getValue().getContainer());
		Assertions.assertEquals(0, scanEntityCaptor.getValue().getEndDateMillis());
		Assertions.assertEquals(ScanStatus.NOT_STARTED, scanEntityCaptor.getValue().getStatus());
	}

	@Test
	public void testMarkScanInProgress() {
		UploadScanEntity scan = new UploadScanEntity();

		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getLatestUploadScan()).thenReturn(scan);

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);

		this.scanResultService.markScanInProgress("ticket");
		Assertions.assertEquals(ScanStatus.IN_PROGRESS, scan.getStatus());
	}

	@Test
	public void testMarkScanFailed() {
		UploadScanEntity scan = new UploadScanEntity();

		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getLatestUploadScan()).thenReturn(scan);

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);

		String message = "message";
		this.scanResultService.markScanFailed("ticket", message);
		Assertions.assertEquals(ScanStatus.FAILED, scan.getStatus());
		Assertions.assertEquals(message, scan.getError());
	}

	@Test
	public void testSaveFinalUploadScan() {
		UploadScanEntity scan = new UploadScanEntity();

		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getLatestUploadScan()).thenReturn(scan);

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);
		BDDMockito.when(mockUploadRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(invoke -> invoke.getArgument(0));
		BDDMockito.when(mockScanRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(invoke -> invoke.getArgument(0));

		UploadViolationEntity violation = new UploadViolationEntity();
		List<UploadViolationEntity> violations = Arrays.asList(violation);

		this.scanResultService.saveFinalUploadScan("ticket", violations);

		Assertions.assertEquals(ScanStatus.DONE, scan.getStatus());
		Assertions.assertEquals(scan, violation.getScan());
	}

	@Test
	public void testGenerateFailedUploadResult() {
		String reason = "reason";
		String name = "name";
		long submitted = System.currentTimeMillis();
		String user = "user";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setUser(user);

		UploadScanResult result = this.scanResultService.generateFailedUploadResult(scan, reason);
		Assertions.assertEquals(reason, result.getErrorMessage());
		Assertions.assertEquals(ScanStatus.FAILED.getDisplayName(), result.getStatus());
		Assertions.assertEquals(name, result.getName());
		Assertions.assertEquals(user, result.getSubmittedBy());
	}

	@Test
	public void testGenerateResultForTicketDone() {
		String name = "name";
		String user = "user";
		String ticket = "ticket";
		String ruleset = "ruleset";

		LocalDateTime submitDate = LocalDateTime.now().minus(1, ChronoUnit.HOURS);
		LocalDateTime endDate = LocalDateTime.now();
		ScanStatus status = ScanStatus.DONE;
		String error = "error";

		String vioName = "vioName";
		int lineNum = 1;
		RulePriority severity = RulePriority.HIGH;
		String fileName = "fileName";

		String ruleMessage = "ruleMessage";

		RuleEntity rule = BDDMockito.mock(RuleEntity.class);
		BDDMockito.when(rule.getMessage()).thenReturn(ruleMessage);
		// first null, then the rule
		BDDMockito.when(mockRuleService.getRule(BDDMockito.anyString())).thenReturn(null)
				.thenReturn(rule);

		UploadViolationEntity vio =
				makeViolationEntity(vioName, lineNum, severity, fileName);

		UploadScanEntity scan = makeScanEntity(submitDate, endDate, status, error, vio, vio);

		UploadScanContainerEntity container = makeScanContainer(name, user, ticket, ruleset, scan);

		BDDMockito.when(scan.getContainer()).thenReturn(container);
		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);

		UploadScanResult result = this.scanResultService.generateResultForTicket("ticket");

		Assertions.assertEquals(name, result.getName());
		Assertions.assertEquals(user, result.getSubmittedBy());
		Assertions.assertEquals(ticket, result.getTicket());
		Assertions.assertEquals(ruleset, result.getRuleset());
		Assertions.assertEquals(submitDate, result.getSubmitDate());
		Assertions.assertEquals(status.getDisplayName(), result.getStatus());
		Assertions.assertEquals(error, result.getErrorMessage());
		Assertions.assertEquals(endDate, result.getEndDate());
		Assertions.assertEquals(2, result.getViolationsFound());

		UploadScanResultViolation vio1 = result.getViolations().get(0);
		Assertions.assertEquals(vioName, vio1.getViolationName());
		Assertions.assertEquals(lineNum, vio1.getLineNumber());
		Assertions.assertEquals(severity.getName(), vio1.getSeverity());
		Assertions.assertEquals(fileName, vio1.getFileName());
		Assertions.assertEquals("Rule guidance not found", vio1.getMessage());

		UploadScanResultViolation vio2 = result.getViolations().get(1);
		Assertions.assertEquals(vioName, vio2.getViolationName());
		Assertions.assertEquals(lineNum, vio2.getLineNumber());
		Assertions.assertEquals(severity.getName(), vio2.getSeverity());
		Assertions.assertEquals(fileName, vio2.getFileName());
		Assertions.assertEquals(ruleMessage, vio2.getMessage());
	}


	@Test
	public void testGenerateResultForTicketInProgress() {
		String name = "name";
		String user = "user";
		String ticket = "ticket";
		String ruleset = "ruleset";

		LocalDateTime submitDate = LocalDateTime.now().minus(1, ChronoUnit.HOURS);
		LocalDateTime endDate = LocalDateTime.now();
		ScanStatus status = ScanStatus.IN_PROGRESS;
		String error = "error";

		UploadScanEntity scan = makeScanEntity(submitDate, endDate, status, error);

		UploadScanContainerEntity container = makeScanContainer(name, user, ticket, ruleset, scan);

		BDDMockito.when(scan.getContainer()).thenReturn(container);

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);

		UploadScanResult result = this.scanResultService.generateResultForTicket("ticket");

		Assertions.assertEquals(name, result.getName());
		Assertions.assertEquals(user, result.getSubmittedBy());
		Assertions.assertEquals(ticket, result.getTicket());
		Assertions.assertEquals(ruleset, result.getRuleset());
		Assertions.assertEquals(submitDate, result.getSubmitDate());
		Assertions.assertEquals(status.getDisplayName(), result.getStatus());
		Assertions.assertEquals(error, result.getErrorMessage());
		Assertions.assertEquals(null, result.getEndDate());
		Assertions.assertEquals(0, result.getViolationsFound());
	}


	@Test
	public void testGenerateResultForTicketNotStarted() {
		String name = "name";
		String user = "user";
		String ticket = "ticket";
		String ruleset = "ruleset";

		ScanStatus status = ScanStatus.NOT_STARTED;

		UploadScanContainerEntity container = makeScanContainer(name, user, ticket, ruleset, null);

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(container);

		UploadScanResult result = this.scanResultService.generateResultForTicket("ticket");

		Assertions.assertEquals(name, result.getName());
		Assertions.assertEquals(user, result.getSubmittedBy());
		Assertions.assertEquals(ticket, result.getTicket());
		Assertions.assertEquals(ruleset, result.getRuleset());
		Assertions.assertEquals(null, result.getSubmitDate());
		Assertions.assertEquals(status.getDisplayName(), result.getStatus());
		Assertions.assertEquals(null, result.getErrorMessage());
		Assertions.assertEquals(null, result.getEndDate());
		Assertions.assertEquals(0, result.getViolationsFound());
	}

	@Test
	public void testGenerateResultForTicketFailed() {
		ScanStatus status = ScanStatus.FAILED;

		BDDMockito.when(mockUploadRepo.findByTicket(BDDMockito.anyString())).thenReturn(null);

		UploadScanResult result = this.scanResultService.generateResultForTicket("ticket");

		Assertions.assertEquals("UNKNOWN", result.getName());
		Assertions.assertEquals(null, result.getSubmittedBy());
		Assertions.assertEquals(null, result.getTicket());
		Assertions.assertEquals(null, result.getRuleset());
		Assertions.assertEquals(null, result.getSubmitDate());
		Assertions.assertEquals(status.getDisplayName(), result.getStatus());
		Assertions.assertEquals("Unknown Ticket", result.getErrorMessage());
		Assertions.assertEquals(null, result.getEndDate());
		Assertions.assertEquals(0, result.getViolationsFound());
	}

	@Test
	public void testGetScanResultsWithFilters() {
		String name = "name";
		String user = "user";
		String ticket = "ticket";
		String ruleset = "ruleset";

		LocalDateTime submitDate = LocalDateTime.now().minus(1, ChronoUnit.HOURS);
		LocalDateTime endDate = LocalDateTime.now();
		ScanStatus status = ScanStatus.DONE;
		String error = "error";

		String vioName = "vioName";
		int lineNum = 1;
		RulePriority severity = RulePriority.HIGH;
		String fileName = "fileName";

		UploadViolationEntity vio =
				makeViolationEntity(vioName, lineNum, severity, fileName);
		UploadScanEntity scan = makeScanEntity(submitDate, endDate, status, error, vio, vio);
		UploadScanContainerEntity container = makeScanContainer(name, user, ticket, ruleset, scan);

		BDDMockito.when(scan.getContainer()).thenReturn(container);

		BDDMockito.when(mockScanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(scan)));
		BDDMockito.when(mockVioRepo.findAllGroupByScan(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(scan)));
		BDDMockito
				.when(mockScanRepo.findByStatusIn(BDDMockito.any(),
						BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Arrays.asList(scan)));

		for (UploadResultFilter filter : Arrays.asList(UploadResultFilter.ALL,
				UploadResultFilter.VIOLATIONS, UploadResultFilter.INCOMPLETE)) {
			List<UploadScanResult> results =
					scanResultService.getScanResultsWithFilters(filter, 10, 0);

			Assertions.assertEquals(1, results.size());
			UploadScanResult result = results.get(0);
			Assertions.assertEquals(name, result.getName());
			Assertions.assertEquals(user, result.getSubmittedBy());
			Assertions.assertEquals(status.getDisplayName(), result.getStatus());
			Assertions.assertEquals(error, result.getErrorMessage());
			Assertions.assertEquals(ticket, result.getTicket());
			Assertions.assertEquals(ruleset, result.getRuleset());
			Assertions.assertEquals(submitDate, result.getSubmitDate());
			Assertions.assertEquals(endDate, result.getEndDate());
			Assertions.assertEquals(2, result.getViolationsFound());
			UploadScanResultViolation violation = result.getViolations().get(0);
			Assertions.assertEquals(vioName, violation.getViolationName());
			Assertions.assertEquals(lineNum, violation.getLineNumber());
			Assertions.assertEquals(severity.getName(), violation.getSeverity());
			Assertions.assertEquals(fileName, violation.getFileName());
			Assertions.assertEquals("Rule guidance not found", violation.getMessage());
		}
	}

	private UploadViolationEntity makeViolationEntity(String vioName, int lineNum,
			RulePriority severity, String fileName) {
		UploadViolationEntity vio = BDDMockito.mock(UploadViolationEntity.class);
		BDDMockito.when(vio.getViolationName()).thenReturn(vioName);
		BDDMockito.when(vio.getLineNum()).thenReturn(lineNum);
		BDDMockito.when(vio.getSeverity()).thenReturn(severity);
		BDDMockito.when(vio.getFileName()).thenReturn(fileName);
		return vio;
	}

	private UploadScanContainerEntity makeScanContainer(String name, String user, String ticket,
			String ruleset, UploadScanEntity scan) {
		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getName()).thenReturn(name);
		BDDMockito.when(container.getSubmitter()).thenReturn(user);
		BDDMockito.when(container.getTicket()).thenReturn(ticket);
		BDDMockito.when(container.getRuleSet()).thenReturn(ruleset);
		BDDMockito.when(container.getLatestUploadScan()).thenReturn(scan);
		return container;
	}

	private UploadScanEntity makeScanEntity(LocalDateTime submitDate, LocalDateTime endDate,
			ScanStatus status, String error, UploadViolationEntity... violations) {
		UploadScanEntity scan = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(scan.getSubmitDate()).thenReturn(submitDate);
		BDDMockito.when(scan.getEndDate()).thenReturn(endDate);
		BDDMockito.when(scan.getStatus()).thenReturn(status);
		BDDMockito.when(scan.getError()).thenReturn(error);
		BDDMockito.when(scan.getViolations()).thenReturn(Arrays.asList(violations));
		return scan;
	}
}

package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.Arrays;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanReportTests;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScanTest;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntityTest;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;

@ExtendWith(SpringExtension.class)
public class ImageScanAgentTest {

	@Test
	public void testInitializeNoApi() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		IImageScanner scanner = BDDMockito.mock(IImageScanner.class);
		RulesetDto ruleset = BDDMockito.mock(RulesetDto.class);
		ImageScanAgent agent = new ImageScanAgent(scan)
				.withScanners(Arrays.asList(scanner))
				.withRuleset(ruleset);
		try {
			agent.initialize();
			Assertions.fail("Should have thrown Exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("API must be configured"));
		}
	}

	@Test
	public void testInitializeNoResultService() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		IImageScanner scanner = BDDMockito.mock(IImageScanner.class);
		RulesetDto ruleset = BDDMockito.mock(RulesetDto.class);
		ImageScanAgent agent = new ImageScanAgent(scan)
				.withScanners(Arrays.asList(scanner))
				.withRuleset(ruleset)
				.withApi(BDDMockito.mock(IImageApi.class));
		try {
			agent.initialize();
			Assertions.fail("Should have thrown Exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Scan Result Service"));
		}
	}

	@Test
	public void testInitializeNoAdvisoryService() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		IImageScanner scanner = BDDMockito.mock(IImageScanner.class);
		ImageScanResultService scanResultService = BDDMockito.mock(ImageScanResultService.class);
		RulesetDto ruleset = BDDMockito.mock(RulesetDto.class);
		ImageScanAgent agent = new ImageScanAgent(scan)
				.withScanners(Arrays.asList(scanner))
				.withRuleset(ruleset)
				.withScanResultService(scanResultService)
				.withApi(BDDMockito.mock(IImageApi.class));
		try {
			agent.initialize();
			Assertions.fail("Should have thrown Exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Image Advisory Service"));
		}
	}

	@Test
	public void testCreateScanConfig() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		ImageSecurityReport report = new ImageSecurityReport(scan);
		IImageApi mockApi = BDDMockito.mock(IImageApi.class);
		BDDMockito.when(mockApi.getSecurityReportForImage(scan)).thenReturn(report);
		IImageScanner scanner = BDDMockito.mock(IImageScanner.class);
		ImageScanResultService scanResultService = BDDMockito.mock(ImageScanResultService.class);
		RulesetDto ruleset = BDDMockito.mock(RulesetDto.class);
		ImageScanAgent agent = new ImageScanAgent(scan)
				.withScanners(Arrays.asList(scanner))
				.withScanResultService(scanResultService)
				.withRuleset(ruleset)
				.withApi(mockApi);
		ImageScanConfig config = agent.createScanConfig();
		Assertions.assertEquals(report, config.getSecurityReport());
	}

	@Test
	public void testReportViolations() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();

		ImageScanViolation violation = ImageScanReportTests.buildStandardImageScanViolation();
		ImageScanReport report = new ImageScanReport();
		report.addViolation(violation);
		report.addError(ImageScanReportTests.buildStandardError());

		ImageAdvisoryService advisoryService = BDDMockito.mock(ImageAdvisoryService.class);
		BDDMockito.when(advisoryService.getOrCreateAdvisory(BDDMockito.any()))
				.thenReturn(AdvisoryEntityTest.buildStandardAdvisory());

		RulesetDto ruleset = new RulesetDto();
		ruleset.setBlockingLevel(violation.getSeverity());

		IImageApi mockApi = BDDMockito.mock(IImageApi.class);
		ImageScanResultService scanResultService = BDDMockito.mock(ImageScanResultService.class);

		IImageScanner scanner = BDDMockito.mock(IImageScanner.class);
		ImageScanAgent agent = new ImageScanAgent(scan)
				.withScanners(Arrays.asList(scanner))
				.withScanResultService(scanResultService)
				.withAdvisoryService(advisoryService)
				.withApi(mockApi)
				.withRuleset(ruleset);

		agent.report(Arrays.asList(report));

		ArgumentCaptor<List> vioCapture =
				ArgumentCaptor.forClass(List.class);
		ArgumentCaptor<ImageScan> imgCapture =
				ArgumentCaptor.forClass(ImageScan.class);
		BDDMockito.verify(mockApi).rejectImage(imgCapture.capture(), vioCapture.capture());
		Assertions.assertEquals(1, vioCapture.getValue().size());
		Assertions.assertEquals(scan, imgCapture.getValue());
	}

}

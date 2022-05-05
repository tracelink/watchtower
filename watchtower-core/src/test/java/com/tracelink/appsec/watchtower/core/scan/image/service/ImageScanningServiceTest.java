package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class ImageScanningServiceTest {
	@MockBean
	private RepositoryService repoService;
	@MockBean
	private ScanRegistrationService scanRegistrationService;
	@MockBean
	private ApiIntegrationService apiService;
	@MockBean
	private LogsService logService;
	@MockBean
	private ImageScanResultService scanResultService;
	@MockBean
	private ImageAdvisoryService imageAdvisoryService;

	private ImageScanningService scanningService;

	@Mock
	private ImageScan mockScan;

	@BeforeEach
	public void setup() {
		BDDMockito.when(logService.getLogsLevel()).thenReturn(Level.INFO);
		this.scanningService =
				new ImageScanningService(repoService, scanRegistrationService, apiService,
						logService, scanResultService, imageAdvisoryService);
	}

	@Test
	public void testDoImageScanSuccess() throws Exception {
		setupDefaultMocks();

		IImageApi mockApi = BDDMockito.mock(IImageApi.class);
		// Test that scan runs as expected
		BDDMockito.when(scanRegistrationService.hasImageScanners()).thenReturn(true);
		BDDMockito.when(scanRegistrationService.getImageScanners())
				.thenReturn(Collections.singleton(new MockScanner()));
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(apiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);
		scanningService.doImageScan(mockScan);
		// ran without exceptions is expected
	}

	@Test
	public void testDoImageScanQuiesced() throws Exception {
		scanningService.quiesce();
		try {
			scanningService.doImageScan(mockScan);
			Assertions.fail("Should have thrown exception");
		} catch (ScanRejectedException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Quiesced"));
		}
	}

	@Test
	public void testDoImageScanNoRuleset() throws Exception {
		BDDMockito.when(
				repoService.upsertRepo(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(new RepositoryEntity());

		scanningService.doImageScan(mockScan);
		BDDMockito.verify(scanRegistrationService, BDDMockito.never()).hasImageScanners();
	}

	@Test
	public void testDoImageScanNoImageScanners() throws Exception {
		setupDefaultMocks();

		BDDMockito.when(scanRegistrationService.hasImageScanners()).thenReturn(false);
		scanningService.doImageScan(mockScan);

		BDDMockito.verify(apiService, BDDMockito.never()).findByLabel(BDDMockito.anyString());
	}

	private void setupDefaultMocks() throws ScanRejectedException {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setRules(Collections.singleton(new MockRuleEntity()));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(ruleset);
		BDDMockito.when(
				repoService.upsertRepo(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(repo);
	}

	private class MockScanner implements IImageScanner {

		@Override
		public ImageScanReport scan(ImageScanConfig config) {
			return null;
		}

		@Override
		public Class<? extends RuleDto> getSupportedRuleClass() {
			return null;
		}
	}
}

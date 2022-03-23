package com.tracelink.appsec.watchtower.core.scan;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

public class ScanRegistrationServiceTest {

	private ScanRegistrationService registrationService;

	@BeforeEach
	public void setup() {
		registrationService = new ScanRegistrationService();
	}

	@Test
	public void testRegister() throws Exception {
		Assertions.assertTrue(registrationService.isEmpty());
		IScanner mockScanner = BDDMockito.mock(IScanner.class);
		BDDMockito.when(mockScanner.getSupportedConfigClass()).thenReturn(ScmScanConfig.class);
		registrationService.registerScanner("mock", mockScanner);
		Assertions.assertFalse(registrationService.isEmpty());
		MatcherAssert.assertThat(registrationService.getScanners(ScmScanConfig.class),
				Matchers.contains(mockScanner));
	}

	@Test
	public void testBlanks() throws Exception {
		IScanner mockScanner = BDDMockito.mock(IScanner.class);
		try {
			registrationService.registerScanner("mock", null);
			Assertions.fail("Should have thrown exception");
		} catch (IllegalArgumentException e) {
		}
		try {
			registrationService.registerScanner("", mockScanner);
			Assertions.fail("Should have thrown exception");
		} catch (IllegalArgumentException e) {
		}
		try {
			registrationService.registerScanner(null, mockScanner);
			Assertions.fail("Should have thrown exception");
		} catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testScannerExists() throws Exception {
		IScanner mockScanner = BDDMockito.mock(IScanner.class);
		registrationService.registerScanner("mock", mockScanner);
		try {
			registrationService.registerScanner("mock", mockScanner);
			Assertions.fail("Should have thrown exception");
		} catch (ModuleException e) {
		}
	}
}

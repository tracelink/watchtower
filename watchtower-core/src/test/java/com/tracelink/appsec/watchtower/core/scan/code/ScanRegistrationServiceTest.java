package com.tracelink.appsec.watchtower.core.scan.code;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

public class ScanRegistrationServiceTest {

	private ScanRegistrationService registrationService;

	@BeforeEach
	public void setup() {
		registrationService = new ScanRegistrationService();
	}

	@Test
	public void testRegister() throws Exception {
		Assertions.assertFalse(registrationService.hasCodeScanners());
		ICodeScanner mockScanner = BDDMockito.mock(ICodeScanner.class);
		registrationService.registerScanner("mock", mockScanner);
		Assertions.assertTrue(registrationService.hasCodeScanners());
		MatcherAssert.assertThat(registrationService.getCodeScanners(),
				Matchers.contains(mockScanner));
	}

	@Test
	public void testBlanks() throws Exception {
		ICodeScanner mockScanner = BDDMockito.mock(ICodeScanner.class);
		try {
			registrationService.registerScanner("mock", (ICodeScanner) null);
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
		ICodeScanner mockScanner = BDDMockito.mock(ICodeScanner.class);
		registrationService.registerScanner("mock", mockScanner);
		try {
			registrationService.registerScanner("mock", mockScanner);
			Assertions.fail("Should have thrown exception");
		} catch (ModuleException e) {
		}
	}
}

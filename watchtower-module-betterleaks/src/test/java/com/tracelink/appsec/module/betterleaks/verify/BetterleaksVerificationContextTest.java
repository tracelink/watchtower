package com.tracelink.appsec.module.betterleaks.verify;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

/**
 * Wires "Verify live" into a full context the way production enables it, and runs the worker's
 * queries against the migrated schema.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class,
		properties = BetterleaksVerificationService.ENABLED_PROPERTY + "=true")
public class BetterleaksVerificationContextTest {

	@Autowired
	private List<ILiveVerifier> verifiers;

	@Autowired
	private AlertTypeRegistry alertTypes;

	@Autowired
	private BetterleaksVerificationWorker worker;

	@Test
	public void testEnablingVerificationRegistersTheVerifierAndItsAlertTypes() {
		Assertions.assertEquals(1, verifiers.size());
		Assertions.assertInstanceOf(BetterleaksVerificationService.class, verifiers.get(0));
		Assertions.assertTrue(alertTypes.get(BetterleaksVerificationWorker.SECRET_LIVE)
				.isPresent());
	}

	@Test
	public void testAPollRunsAgainstTheMigratedSchema() {
		Assertions.assertDoesNotThrow(() -> worker.poll());
	}
}

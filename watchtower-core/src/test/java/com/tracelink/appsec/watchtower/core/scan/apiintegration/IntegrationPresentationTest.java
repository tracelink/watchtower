package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrRejectOption;

class IntegrationPresentationTest {

	private static final long CHECKED = 1_800_000_000_000L;

	@Test
	void anIntegrationNeverCheckedSaysSo() {
		IntegrationPresentation.Chip chip =
				IntegrationPresentation.connection(new BBCloudIntegrationEntity(), false);
		Assertions.assertEquals("Not checked", chip.label());
		Assertions.assertNull(chip.tipMillis());
	}

	@Test
	void aPassedCheckIsConnectedWithTheTimeOnHover() {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setHealth(CHECKED, true, null);
		IntegrationPresentation.Chip chip = IntegrationPresentation.connection(bb, false);
		Assertions.assertEquals("Connected", chip.label());
		Assertions.assertEquals("success", chip.tone());
		Assertions.assertEquals(CHECKED, chip.tipMillis());
	}

	@Test
	void aRecentFailureIsFailingWithItsReasonAndAnOldOneIsQuieter() {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setHealth(CHECKED, false, "401 Unauthorized");
		IntegrationPresentation.Chip failing = IntegrationPresentation.connection(bb, true);
		Assertions.assertEquals("Key rejected", failing.label());
		Assertions.assertEquals("danger", failing.tone());
		Assertions.assertTrue(failing.tip().startsWith("Bitbucket rejected the saved key"));
		Assertions.assertEquals("401 Unauthorized", IntegrationPresentation.failureDetail(bb),
				"the raw error is behind Details");
		Assertions.assertEquals("neutral", IntegrationPresentation.connection(bb, false).tone());

		bb.setHealth(CHECKED, false, "Connection timed out");
		Assertions.assertEquals("Failing", IntegrationPresentation.connection(bb, true).label());
	}

	@Test
	void anAwsRejectedKeyReadsInPlainWords() {
		// Dev's Example ECR check (Fixes board, 2026-10-22).
		EcrIntegrationEntity ecr = new EcrIntegrationEntity();
		ecr.setHealth(CHECKED, false, "Cannot create stack via CloudFormation: The security token included in"
				+ " the request is invalid. (Service: CloudFormation, Status Code: 403, Request ID: 58a1)");
		IntegrationPresentation.Chip chip = IntegrationPresentation.connection(ecr, true);
		Assertions.assertEquals("Key rejected", chip.label());
		Assertions.assertTrue(chip.tip().startsWith("AWS rejected the saved key. Replace the key"));
		Assertions.assertFalse(chip.tip().contains("CloudFormation"), "the raw error is not on the chip");
		Assertions.assertTrue(IntegrationPresentation.failureDetail(ecr).contains("Status Code: 403"));
	}

	@Test
	void anErrorThatIsWatchtowersOwnIsNotBlamedOnTheProvider() {
		// The ECR check failed on Dev with this before it stopped needing a web request
		EcrIntegrationEntity ecr = new EcrIntegrationEntity();
		ecr.setHealth(CHECKED, false, "No current ServletRequestAttributes");
		IntegrationPresentation.Chip chip = IntegrationPresentation.connection(ecr, true);
		Assertions.assertEquals("Couldn't check", chip.label());
		Assertions.assertEquals("warning", chip.tone());
		Assertions.assertFalse(chip.tip().contains("ServletRequestAttributes"));

		ecr.setHealth(CHECKED, false, IntegrationPresentation.COULD_NOT_RUN + "boom");
		Assertions.assertEquals("Couldn't check", IntegrationPresentation.connection(ecr, true).label());
	}

	@Test
	void theWebhookReadsInPlainWords() {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setRegisterState(RegisterState.NOT_REGISTERED);
		Assertions.assertEquals("Workspace not set up", IntegrationPresentation.webhook(bb).label());
		bb.setRegisterState(RegisterState.REGISTERED);
		Assertions.assertEquals("Workspace", IntegrationPresentation.webhook(bb).label());
		bb.setRegisterState(RegisterState.FAILED);
		bb.setRegisterError("403 Forbidden");
		Assertions.assertTrue(IntegrationPresentation.webhook(bb).tip().startsWith("403 Forbidden"));
		bb.setRegisterState(RegisterState.NOT_SUPPORTED);
		Assertions.assertNull(IntegrationPresentation.webhook(bb));
	}

	@Test
	void aWorkspaceHookNobodyHasCheckedYetIsNotSaidToBeInactive() {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setRegisterState(RegisterState.REGISTERED);
		bb.setCachedWebhookRepositories(0L);

		// never checked: unknown, not "No active workspace hook"
		Assertions.assertEquals("Workspace hook not checked yet", IntegrationPresentation.webhook(bb).label());
		bb.setCachedWorkspaceActive(false);
		Assertions.assertEquals("No active workspace hook", IntegrationPresentation.webhook(bb).label());
		bb.setCachedWorkspaceActive(true);
		Assertions.assertEquals("Workspace", IntegrationPresentation.webhook(bb).label());
	}

	@Test
	void aWorkspaceHookPlusRepositoryHooksSaysWhatIsDoubledAndWhatToDo() {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setRegisterState(RegisterState.REGISTERED);
		bb.setCachedWorkspaceActive(true);
		bb.setCachedWebhookRepositories(1L);

		var chip = IntegrationPresentation.webhook(bb);

		Assertions.assertEquals("Workspace + 1 repo hook", chip.label());
		Assertions.assertTrue(chip.tip().contains("workspace hook already covers every repository"));
		Assertions.assertTrue(chip.tip().contains("scanned once"));
		bb.setCachedWebhookRepositories(3L);
		Assertions.assertEquals("Workspace + 3 repo hooks", IntegrationPresentation.webhook(bb).label());
	}

	@Test
	void everyStoredChoiceIsOfferedInPlainWords() {
		List<String> bitbucket = IntegrationPresentation.blockChoices(ApiType.BITBUCKET_CLOUD).stream()
				.map(IntegrationPresentation.Choice::value).toList();
		Assertions.assertEquals(Arrays.stream(BBCloudRejectOption.values())
				.map(BBCloudRejectOption::getName).toList(), bitbucket);
		List<String> ecr = IntegrationPresentation.blockChoices(ApiType.ECR).stream()
				.map(IntegrationPresentation.Choice::value).toList();
		Assertions.assertEquals(Arrays.stream(EcrRejectOption.values())
				.map(EcrRejectOption::getName).toList(), ecr);
		Assertions.assertEquals("Comment and block",
				IntegrationPresentation.blockChoices(ApiType.BITBUCKET_CLOUD).get(2).label());
	}
}

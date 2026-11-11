package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class PRCommentCommandTest {

	@Test
	void bypassCommandGivesTheReason() {
		assertEquals(Optional.of("Hotfix for the outage"),
				PRCommentCommand.bypassReason("/watchtower bypass Hotfix for the outage"));
	}

	@Test
	void commandIsCaseInsensitiveAndMayBeIndented() {
		assertEquals(Optional.of("Hotfix"),
				PRCommentCommand.bypassReason("  /Watchtower BYPASS   Hotfix  "));
	}

	@Test
	void reasonMayContinueOnTheNextLines() {
		assertEquals(Optional.of("Test fixture,\nnot a real key"),
				PRCommentCommand.bypassReason("/watchtower bypass Test fixture,\nnot a real key\n"));
		assertEquals(Optional.of("Test fixture"),
				PRCommentCommand.bypassReason("/watchtower bypass\nTest fixture"));
	}

	@Test
	void missingReasonIsAnEmptyReason() {
		// The caller answers with how to add one; this is still a bypass command.
		assertEquals(Optional.of(""), PRCommentCommand.bypassReason("/watchtower bypass"));
	}

	@Test
	void ordinaryCommentsAreNotCommands() {
		assertEquals(Optional.empty(), PRCommentCommand.bypassReason("Looks good to me"));
		assertEquals(Optional.empty(), PRCommentCommand.bypassReason(null));
		// Only on the first line: quoting the command in a sentence does nothing.
		assertEquals(Optional.empty(),
				PRCommentCommand.bypassReason("To skip it, comment:\n/watchtower bypass <reason>"));
		assertEquals(Optional.empty(),
				PRCommentCommand.bypassReason("/watchtower bypassing is easy"));
		assertEquals(Optional.empty(), PRCommentCommand.bypassReason("/watchtower help"));
	}

	@Test
	void commandFormattedAsCodeIsStillTheCommand() {
		// Bitbucket stores a pasted or formatted command with backticks, as in the bot's own hint
		// "comment `/watchtower bypass <reason>`". This was ignored with no reply at all.
		assertEquals(Optional.of("THESE ARE DUMMY CREDS"),
				PRCommentCommand.bypassReason("`/watchtower bypass` THESE ARE DUMMY CREDS"));
		assertEquals(Optional.of("THESE ARE DUMMY CREDS"),
				PRCommentCommand.bypassReason("`/watchtower bypass THESE ARE DUMMY CREDS`"));
		assertEquals(Optional.of("THESE ARE DUMMY CREDS"),
				PRCommentCommand.bypassReason("  ``/watchtower bypass`` THESE ARE DUMMY CREDS\n"));
		assertEquals(Optional.of(""), PRCommentCommand.bypassReason("`/watchtower bypass`"));
		assertEquals(BypassReasonCode.FALSE_POSITIVE,
				PRCommentCommand.reasonCode("`/watchtower bypass` fp matcher is too broad"));
		assertEquals(Optional.of("matcher is too broad"),
				PRCommentCommand.bypassReason("`/watchtower bypass` fp matcher is too broad"));
	}

	@Test
	void aReasonKeepsItsOwnBackticks() {
		assertEquals(Optional.of("the `key` is a fixture"),
				PRCommentCommand.bypassReason("/watchtower bypass the `key` is a fixture"));
		assertEquals(Optional.of("the `key` is a fixture"),
				PRCommentCommand.bypassReason("`/watchtower bypass` the `key` is a fixture"));
	}

	@Test
	void codeFormattedTextThatIsNotTheCommandIsStillNotACommand() {
		assertEquals(Optional.empty(), PRCommentCommand.bypassReason("`/watchtower bypassing` is easy"));
		assertEquals(Optional.empty(),
				PRCommentCommand.bypassReason("To skip it, comment `/watchtower bypass <reason>`"));
	}

	@Test
	void mentionCheckIsCheapAndCaseInsensitive() {
		assertTrue(PRCommentCommand.mayContainCommand("{\"raw\":\"/WATCHTOWER bypass x\"}"));
		assertFalse(PRCommentCommand.mayContainCommand("{\"raw\":\"Looks good\"}"));
		assertFalse(PRCommentCommand.mayContainCommand(null));
	}
 @Test void typedReasonCategoriesAreIndependentOfFindingLabels(){
  assertEquals(BypassReasonCode.FALSE_POSITIVE,PRCommentCommand.reasonCode("/watchtower bypass fp matcher is too broad"));
  assertEquals(Optional.of("matcher is too broad"),PRCommentCommand.bypassReason("/watchtower bypass fp matcher is too broad"));
  assertEquals(BypassReasonCode.ACCEPTED_RISK,PRCommentCommand.reasonCode("/watchtower bypass risk emergency release"));
  assertEquals(BypassReasonCode.OTHER,PRCommentCommand.reasonCode("/watchtower bypass Test fixture"));
 }

}

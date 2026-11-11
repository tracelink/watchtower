package com.tracelink.appsec.watchtower.core.module;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.metrics.ModuleStatus;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;

/** Scanner modules shows the same status as Home, readable names and rule counts. */
class ModuleRowTest {

	@Test
	void statusMatchesHomeForReadySetupAndOff() {
		ICodeScanner ready = mock(ICodeScanner.class);
		ICodeScanner setup = mock(ICodeScanner.class);
		when(setup.setupIssue()).thenReturn("AWS canary and Dev readiness gates have not passed");
		ICodeScanner off = mock(ICodeScanner.class);
		when(off.isDisabled()).thenReturn(true);

		ModuleStatus readyStatus = ModuleStatus.of("PMD", ready);
		ModuleStatus setupStatus = ModuleStatus.of("AwsSecurityAgent", setup);
		ModuleStatus offStatus = ModuleStatus.of("opengrep", off);

		assertEquals("Ready", readyStatus.getStateLabel());
		assertEquals("Enabled and configured.", readyStatus.reason());
		assertEquals("AWS Security Agent", setupStatus.name());
		assertEquals("Needs setup", setupStatus.getStateLabel());
		assertEquals("AWS canary and Dev readiness gates have not passed.", setupStatus.reason());
		assertEquals("Off", offStatus.getStateLabel());
		assertEquals("Opengrep", offStatus.name());
	}

	@Test
	void rulesLabelUsesSingularForOne() {
		ModuleStatus status = new ModuleStatus("JSON", "data_object", "JSON files", ModuleStatus.READY, "Enabled and configured.");
		assertEquals("1 rule", new ModuleRow("json", status, true, 0, 1, "/rule/edit/json").getRulesLabel());
		assertEquals("385 rules", new ModuleRow("betterleaks", status, true, 0, 385, null).getRulesLabel());
	}
}

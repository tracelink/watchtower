package com.tracelink.appsec.watchtower.core.metrics;

import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * One scanner module on Home's status panel. {@code state} is ready, setup or off (the CSS
 * modifier); {@code reason} is the hover text. Built from module policy and settings only: it
 * never tests a provider connection.
 */
public record ModuleStatus(String name, String icon, String purpose, String state, String reason) {
	public static final String READY = "ready";
	public static final String SETUP = "setup";
	public static final String OFF = "off";

	/**
	 * The status of one registered module, the same on Home and on Scanner modules.
	 *
	 * @param module  the registered module name
	 * @param scanner its scanner, wrapped in the module policy
	 * @return the module's status
	 */
	public static ModuleStatus of(String module, IScanner<?, ?> scanner) {
		ScannerIdentity identity = ScannerIdentity.of(module);
		String issue = scanner.isDisabled() ? null : scanner.setupIssue();
		String state = scanner.isDisabled() ? OFF : issue != null ? SETUP : READY;
		String reason = switch (state) {
			case OFF -> "Turned off in Scanner modules.";
			case SETUP -> issue + ".";
			default -> "Enabled and configured.";
		};
		return new ModuleStatus(identity.name(), identity.icon(), identity.purpose(), state, reason);
	}

	public String getStateLabel() {
		return switch (state) {
			case READY -> "Ready";
			case SETUP -> "Needs setup";
			default -> "Off";
		};
	}
}

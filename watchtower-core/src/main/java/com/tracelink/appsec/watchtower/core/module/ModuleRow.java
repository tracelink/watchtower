package com.tracelink.appsec.watchtower.core.module;

import java.util.List;

import com.tracelink.appsec.watchtower.core.metrics.ModuleStatus;

/**
 * One row of Scanner modules: the module's status (the same one Home shows), its execution
 * policy for the On/Off switch and how many rules it has.
 *
 * @param module   registered module name (posted back when the switch changes)
 * @param status   name, icon, purpose and Ready / Needs setup / Off with its reason
 * @param enabled  whether the execution policy is on
 * @param version  policy version for the optimistic check
 * @param rules    number of rules the module has
 * @param rulesUrl its rules on Rule editing, or null when it has no rule editor
 * @param fileTypes the file types its scanner runs on now; empty means every file
 * @param defaultFileTypes the scanner's own default types
 * @param fileTypesCustomized true when an admin chose the types instead of the default
 */
public record ModuleRow(String module, ModuleStatus status, boolean enabled, long version, long rules,
		String rulesUrl, List<String> fileTypes, List<String> defaultFileTypes, boolean fileTypesCustomized) {

	/** A row for a module with no file types (every file). */
	public ModuleRow(String module, ModuleStatus status, boolean enabled, long version, long rules,
			String rulesUrl) {
		this(module, status, enabled, version, rules, rulesUrl, List.of(), List.of(), false);
	}

	/** "1 rule" or "N rules". */
	public String getRulesLabel() {
		return rules + (rules == 1 ? " rule" : " rules");
	}
}

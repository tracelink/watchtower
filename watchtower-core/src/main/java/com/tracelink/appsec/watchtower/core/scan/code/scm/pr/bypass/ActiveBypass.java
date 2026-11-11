package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.Set;

/**
 * What the active bypasses of one pull request cover, together: the union of their findings,
 * named after the newest.
 *
 * @param bypassedBy who made the newest bypass
 * @param reason     its reason
 * @param createdAt  when, in epoch millis
 * @param findings   every covered rule and file
 * @author Watchtower
 */
public record ActiveBypass(String bypassedBy, String reason, long createdAt,
		Set<BypassedFinding> findings) {

	public ActiveBypass {
		findings = Set.copyOf(findings);
	}

	/**
	 * @param ruleName a violation's rule name
	 * @param filePath its repo-relative file
	 * @return true if a blocking finding of that rule in that file no longer blocks
	 */
	public boolean covers(String ruleName, String filePath) {
		return findings.contains(new BypassedFinding(ruleName, filePath));
	}
}

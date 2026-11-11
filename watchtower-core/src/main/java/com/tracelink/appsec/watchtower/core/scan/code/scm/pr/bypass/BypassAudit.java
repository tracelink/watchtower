package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.List;

/**
 * What the bypass audit page shows (§4.16).
 *
 * @param active  bypasses not revoked, newest first
 * @param recent  the newest bypasses, revoked or not
 * @param perRepo bypasses per repository in the counting window, most first
 * @author Watchtower
 */
public record BypassAudit(List<PullRequestBypassEntity> active,
		List<PullRequestBypassEntity> recent, List<RepoBypassCount> perRepo) {

	public BypassAudit {
		active = List.copyOf(active);
		recent = List.copyOf(recent);
		perRepo = List.copyOf(perRepo);
	}
}

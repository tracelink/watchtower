package com.tracelink.appsec.module.betterleaks.allowlist;

import java.time.LocalDate;

/**
 * A new allowlist entry as submitted; validated by {@link BetterleaksAllowlistService}.
 *
 * @param scope     where it applies
 * @param repoName  the repository, required for {@link BetterleaksAllowlistScope#REPO}
 * @param pathGlob  the path glob, or blank
 * @param ruleId    the Betterleaks rule id, or blank
 * @param reason    why the entry is safe (required)
 * @param expiresOn the last day it applies, or null for no expiry
 * @author Watchtower
 */
public record BetterleaksAllowlistRequest(BetterleaksAllowlistScope scope, String repoName,
		String pathGlob, String ruleId, String reason, LocalDate expiresOn) {
}

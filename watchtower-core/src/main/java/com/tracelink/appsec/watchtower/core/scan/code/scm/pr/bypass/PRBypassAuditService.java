package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Reads what the bypass audit page shows (§4.16): who bypassed which pull request and why, and
 * which repositories are bypassed most - a sign that rules need tuning or a team needs help.
 *
 * @author Watchtower
 */
@Service
public class PRBypassAuditService {

	/** The period the per-repository counts cover. */
	static final Duration COUNT_WINDOW = Duration.ofDays(90);

	private final PullRequestBypassRepository bypassRepository;

	private final Clock clock;

	@Autowired
	public PRBypassAuditService(PullRequestBypassRepository bypassRepository) {
		this(bypassRepository, Clock.systemUTC());
	}

	PRBypassAuditService(PullRequestBypassRepository bypassRepository, Clock clock) {
		this.bypassRepository = bypassRepository;
		this.clock = clock;
	}

	/**
	 * @return active bypasses, the newest ones, and per-repository counts for the last 90 days
	 */
	public BypassAudit audit() {
		return new BypassAudit(bypassRepository.findByRevokedAtIsNullOrderByCreatedAtDesc(),
				bypassRepository.findTop200ByOrderByCreatedAtDesc(),
				bypassRepository.countPerRepositorySince(
						clock.millis() - COUNT_WINDOW.toMillis()));
	}
}

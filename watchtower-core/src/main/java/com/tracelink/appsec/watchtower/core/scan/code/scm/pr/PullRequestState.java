package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

/**
 * Identifies the state of a Pull Request
 * <p>
 * Note that this is never persisted - it is a transient property of a
 * {@linkplain PullRequest}, filled from the SCM on each fetch. What the database holds is
 * the {@code resolved} boolean on {@code PullRequestContainerEntity}, derived in part
 * from {@link #isResolved()}. Values may therefore be added without a migration.
 *
 * @author csmith
 *
 */
public enum PullRequestState {
	ACTIVE, DECLINED, MERGED;

	/**
	 * Whether a Pull Request in this state is finished, and so needs no further review.
	 * <p>
	 * Both {@link #MERGED} and {@link #DECLINED} are terminal: the Pull Request is closed
	 * and the SCM will report no further changes to it. Only {@link #ACTIVE} still has
	 * work outstanding.
	 *
	 * @return true if a Pull Request in this state should be treated as resolved
	 */
	public boolean isResolved() {
		return this == DECLINED || this == MERGED;
	}
}

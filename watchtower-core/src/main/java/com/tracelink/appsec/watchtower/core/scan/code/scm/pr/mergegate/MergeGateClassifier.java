package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

import java.util.Collection;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CommitIds;

/**
 * Decides what Watchtower knew about one pull request at the moment it was merged. Pure: it reads
 * only what it is given, so the merge gate view and its tests agree on every case.
 * <p>
 * Example: commit {@code abc} is scanned clean at 10:04 and the pull request is merged at 10:30 -
 * {@link MergeGateOutcome#SCANNED_CLEAN}. A push of {@code def} at 10:00 merged at 10:02 while its
 * scan is queued - {@link MergeGateOutcome#SCAN_IN_PROGRESS}.
 *
 * @author Watchtower
 */
public final class MergeGateClassifier {

	/**
	 * A merged pull request.
	 *
	 * @param mergedAt     when the SCM says it was merged, epoch millis
	 * @param mergedCommit the commit merged, or null when the SCM did not say
	 * @param scanPending  whether a scan of it was queued or running when the merge was seen
	 */
	public record MergedPullRequest(long mergedAt, String mergedCommit, boolean scanPending) {
	}

	/**
	 * One scan of the pull request.
	 *
	 * @param endDate when it completed, epoch millis; 0 if it has not
	 */
	public record Scan(long scanId, String commitHash, ScanStatus status, long endDate,
			boolean blocked) {
	}

	/**
	 * A bypass of the pull request's blocking.
	 *
	 * @param revokedAt when it was revoked, or null if it is still active
	 */
	public record Bypass(long createdAt, Long revokedAt) {
		boolean activeAt(long time) {
			return createdAt <= time && (revokedAt == null || revokedAt > time);
		}
	}

	private MergeGateClassifier() {
	}

	/**
	 * @param pr                     the merged pull request
	 * @param scans                  every scan of it
	 * @param bypasses               every bypass of it
	 * @param scansBypassedWhenFound scans whose blocking findings an active bypass covered when
	 *                               they were found, so the scan itself did not block
	 * @return what Watchtower knew when it was merged
	 */
	public static MergeGateOutcome classify(MergedPullRequest pr, Collection<Scan> scans,
			Collection<Bypass> bypasses, Set<Long> scansBypassedWhenFound) {
		Optional<Scan> gating = gatingScan(pr, scans);
		if (gating.isPresent()) {
			return gated(gating.get(), pr, bypasses, scansBypassedWhenFound);
		}
		// Finished after the merge, passed or failed: it was still running when it happened.
		if (pr.scanPending() || scans.stream().anyMatch(s -> ofMergedCommit(s, pr)
				&& !completedBy(s, pr.mergedAt()))) {
			return MergeGateOutcome.SCAN_IN_PROGRESS;
		}
		if (scans.stream().anyMatch(s -> ofMergedCommit(s, pr) && s.status() == ScanStatus.FAILED
				&& completedBy(s, pr.mergedAt()))) {
			return MergeGateOutcome.SCAN_FAILED;
		}
		if (scans.stream().anyMatch(s -> completedBy(s, pr.mergedAt()))) {
			return MergeGateOutcome.NEWER_COMMIT_NOT_SCANNED;
		}
		return MergeGateOutcome.NEVER_SCANNED;
	}

	/**
	 * @return the scan a merge gate would have checked: the newest completed scan of the merged
	 *         commit that finished before the merge, if there is one
	 */
	public static Optional<Scan> gatingScan(MergedPullRequest pr, Collection<Scan> scans) {
		return scans.stream()
				.filter(s -> s.status() == ScanStatus.DONE && completedBy(s, pr.mergedAt())
						&& ofMergedCommit(s, pr))
				.max(Comparator.comparingLong(Scan::endDate).thenComparingLong(Scan::scanId));
	}

	private static MergeGateOutcome gated(Scan scan, MergedPullRequest pr,
			Collection<Bypass> bypasses, Set<Long> scansBypassedWhenFound) {
		// Findings an active bypass covered when they were found did not block the scan; they
		// were still blocking findings, bypassed only while that bypass lasted.
		if (!scan.blocked() && !scansBypassedWhenFound.contains(scan.scanId())) {
			return MergeGateOutcome.SCANNED_CLEAN;
		}
		return bypasses.stream().anyMatch(b -> b.activeAt(pr.mergedAt()))
				? MergeGateOutcome.BLOCKED_BYPASSED
				: MergeGateOutcome.BLOCKED_UNBYPASSED;
	}

	private static boolean completedBy(Scan scan, long time) {
		return scan.endDate() > 0 && scan.endDate() <= time;
	}

	/**
	 * Without a merged commit from the SCM, any scan counts as one of it. Bitbucket's webhook writes
	 * the commit in 12 characters and its API in 40, so the two are compared as the same commit when
	 * one is a prefix of the other, not for exact equality.
	 */
	private static boolean ofMergedCommit(Scan scan, MergedPullRequest pr) {
		return pr.mergedCommit() == null || pr.mergedCommit().equalsIgnoreCase(scan.commitHash())
				|| CommitIds.same(pr.mergedCommit(), scan.commitHash());
	}
}

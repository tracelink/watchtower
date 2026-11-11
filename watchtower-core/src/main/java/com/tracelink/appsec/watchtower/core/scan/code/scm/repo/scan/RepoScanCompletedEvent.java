package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;

/**
 * Published after a repository scan's report is stored. Listeners (alerts, for one) act only on
 * the findings that are new since the previous scan of the branch, so a first scan, the
 * baseline, raises no per-finding noise.
 *
 * @param scanId      the scan
 * @param apiLabel    the integration
 * @param repository  the repository name
 * @param branch      the branch scanned
 * @param commitHash  the commit scanned
 * @param baseline    true if this was the branch's first scan
 * @param newFindings findings the previous scan did not have; empty on a baseline
 * @author Watchtower
 */
public record RepoScanCompletedEvent(long scanId, String apiLabel, String repository,
		String branch, String commitHash, boolean baseline,
		List<RepoScanReport.Finding> newFindings) {

	public RepoScanCompletedEvent {
		newFindings = newFindings == null ? List.of() : List.copyOf(newFindings);
	}
}

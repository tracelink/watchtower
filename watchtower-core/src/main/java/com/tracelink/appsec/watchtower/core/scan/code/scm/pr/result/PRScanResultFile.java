package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.util.Collections;
import java.util.List;

/**
 * The source of one file that a PR scan raised findings in, shown in the code section at the
 * bottom of the PR scan report.
 * <p>
 * There is exactly one of these per <em>file with findings</em> - not one per violation - so a
 * file flagged ten times renders its source once, with all ten lines highlighted. Files the scan
 * found nothing in are never built, which is why the report only lists files that have issues.
 *
 * @author Watchtower
 */
public class PRScanResultFile {
	private final String fileName;

	private final List<PRScanResultCodeBlock> blocks;

	private final int findingCount;

	private final boolean sourceAvailable;

	private final String sourceUnavailableReason;

	private PRScanResultFile(String fileName, List<PRScanResultCodeBlock> blocks, int findingCount,
			boolean sourceAvailable, String sourceUnavailableReason) {
		this.fileName = fileName;
		this.blocks = List.copyOf(blocks);
		this.findingCount = findingCount;
		this.sourceAvailable = sourceAvailable;
		this.sourceUnavailableReason = sourceUnavailableReason;
	}

	/**
	 * A file whose source was fetched successfully.
	 *
	 * @param fileName     the path of the file, as the scanner reported it
	 * @param blocks       the contiguous runs of source around the findings
	 * @param findingCount how many findings this file has
	 * @return the file entry to render
	 */
	public static PRScanResultFile withSource(String fileName, List<PRScanResultCodeBlock> blocks,
			int findingCount) {
		return new PRScanResultFile(fileName, blocks, findingCount, true, null);
	}

	/**
	 * A file whose source could not be fetched - deleted since the scan ran, renamed, or the SCM
	 * call failed. The report still lists the file and its finding count, but shows an explicit
	 * "source unavailable" state instead of the blank cell the previous layout produced.
	 *
	 * @param fileName     the path of the file, as the scanner reported it
	 * @param findingCount how many findings this file has
	 * @return the file entry to render
	 */
	public static PRScanResultFile withoutSource(String fileName, int findingCount) {
		return withoutSource(fileName, findingCount, null);
	}

	/**
	 * Like {@link #withoutSource(String, int)}, saying why, so the report does not leave a person
	 * guessing whether the file was deleted, too large or the server unreachable.
	 *
	 * @param reason in words for the reader; null when not known
	 */
	public static PRScanResultFile withoutSource(String fileName, int findingCount, String reason) {
		return new PRScanResultFile(fileName, Collections.emptyList(), findingCount, false,
				reason == null || reason.isBlank()
						? "The source control server did not return the file." : reason);
	}

	public String getFileName() {
		return fileName;
	}

	public List<PRScanResultCodeBlock> getBlocks() {
		return blocks;
	}

	public int getFindingCount() {
		return findingCount;
	}

	public boolean isSourceAvailable() {
		return sourceAvailable;
	}

	/** Why there is no code to show, or null when there is. */
	public String getSourceUnavailableReason() {
		return sourceUnavailableReason;
	}
}

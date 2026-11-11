package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Finding counts per severity, highest first, stored on a scan row as {@code "3,0,5,1,0,2"} so a
 * list of scans can show and sort by severity without reading any findings.
 *
 * @author Watchtower
 */
public final class SeverityCounts {

	private static final int LEVELS = RulePriority.values().length;

	private final int[] counts;

	private SeverityCounts(int[] counts) {
		this.counts = counts;
	}

	public static SeverityCounts empty() {
		return new SeverityCounts(new int[LEVELS]);
	}

	/**
	 * @param severities one entry per finding
	 * @return the counts per severity
	 */
	public static SeverityCounts of(Collection<RulePriority> severities) {
		int[] counts = new int[LEVELS];
		for (RulePriority severity : severities) {
			counts[(severity == null ? RulePriority.LOW : severity).ordinal()]++;
		}
		return new SeverityCounts(counts);
	}

	/** These counts plus {@code other}'s, as new counts (neither is changed). */
	public SeverityCounts plus(SeverityCounts other) {
		int[] sum = counts.clone();
		for (int i = 0; i < LEVELS; i++) {
			sum[i] += other == null ? 0 : other.counts[i];
		}
		return new SeverityCounts(sum);
	}

	/**
	 * @param stored the stored form, may be null or malformed
	 * @return the parsed counts; any unreadable value counts as 0
	 */
	public static SeverityCounts parse(String stored) {
		int[] counts = new int[LEVELS];
		if (StringUtils.isNotBlank(stored)) {
			String[] parts = stored.split(",");
			for (int i = 0; i < Math.min(parts.length, LEVELS); i++) {
				try {
					counts[i] = Math.max(0, Integer.parseInt(parts[i].trim()));
				} catch (NumberFormatException e) {
					counts[i] = 0;
				}
			}
		}
		return new SeverityCounts(counts);
	}

	public String format() {
		return String.join(",", Arrays.stream(counts).mapToObj(String::valueOf).toList());
	}

	public int get(RulePriority severity) {
		return counts[severity.ordinal()];
	}

	public int total() {
		return Arrays.stream(counts).sum();
	}

	/**
	 * @return the total excluding informational findings, as the dashboards count them
	 */
	public int totalExcludingInformational() {
		return total() - get(RulePriority.INFORMATIONAL);
	}

	/**
	 * @return the severities with findings, highest first, for severity chips
	 */
	public List<Level> levels() {
		return Arrays.stream(RulePriority.values()).filter(p -> counts[p.ordinal()] > 0)
				.map(p -> new Level(p.getName(), p.getPriority(), counts[p.ordinal()])).toList();
	}

	/**
	 * One severity's count.
	 *
	 * @param name  the severity's name
	 * @param value its priority number, 1 (high) to 6 (informational)
	 * @param count how many findings
	 */
	public record Level(String name, int value, int count) {
	}

	/**
	 * @return the highest severity with any finding, or null if there are none
	 */
	public RulePriority highest() {
		for (RulePriority severity : RulePriority.values()) {
			if (counts[severity.ordinal()] > 0) {
				return severity;
			}
		}
		return null;
	}
}

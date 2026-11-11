package com.tracelink.appsec.watchtower.core.metrics;

import java.util.List;
import java.util.Map;

/**
 * One tile of Home's "Needs a person" strip: a Rule work queue, its item count and where to open
 * it. Setup gaps are housekeeping (missing owner or CWE), not a quality problem, so they are
 * styled apart from the queues that need a decision.
 */
public record HomeWorkTile(String queue, String icon, String label, String tip, long count) {

	private static final List<HomeWorkTile> TEMPLATES = List.of(
			new HomeWorkTile("review", "rate_review", "Findings to review",
					"Recent findings nobody has marked true or false positive yet.", 0),
			new HomeWorkTile("investigate", "troubleshoot", "Rules to investigate",
					"Rules people reported as noisy (many false positives).", 0),
			new HomeWorkTile("reviews", "event_busy", "Reviews due",
					"Rule reviews assigned to someone that are due or overdue.", 0),
			new HomeWorkTile("candidates", "science", "Rule changes to test",
					"Proposed rule changes waiting for a test or a decision.", 0),
			new HomeWorkTile("setup", "build", "Setup gaps",
					"Rules missing an owner or CWE. Housekeeping, not a quality problem.", 0));

	/** Tiles for the queues the viewer may see (a null count means hidden), in Rule work's order. */
	public static List<HomeWorkTile> from(Map<String, Long> counts) {
		return TEMPLATES.stream().filter(tile -> counts.get(tile.queue()) != null)
				.map(tile -> new HomeWorkTile(tile.queue(), tile.icon(), tile.label(), tile.tip(),
						counts.get(tile.queue())))
				.toList();
	}

	public String getUrl() {
		return "/rules/work?queue=" + queue;
	}

	/** active: needs a decision now; zero: nothing waiting; setup: housekeeping. */
	public String getTone() {
		if ("setup".equals(queue)) return "setup";
		return count > 0 ? "active" : "zero";
	}
}

package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriUtils;

import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * Links from a rule in the work overview to recent reports where it matched, opened pre-filtered
 * to the rule so "Review finding" is one click away. Report contents are never read here.
 */
@Component
@Transactional(readOnly = true)
public class RuleWorkLinks {
	static final int REPORTS_PER_RULE = 3;

	private final LedgerRepository records;

	public RuleWorkLinks(LedgerRepository records) {
		this.records = records;
	}

	public record Link(String label, String url) {
	}

	/** A rule's id, name and current revision: all the links need, without loading the rule. */
	public record RuleRef(long id, String name, String revision) {
	}

	/**
	 * Up to three recent matched scans per rule for its current revision. One small query per rule
	 * walks the (rule_id, revision, bucket_start) index backwards, so a busy rule cannot crowd out
	 * the others and nothing is sorted in memory.
	 */
	public Map<Long, List<Link>> matchedReports(List<RuleRef> rules, long since) {
		Map<Long, List<Map<String, Object>>> scans = new LinkedHashMap<>();
		for (RuleRef rule : rules) {
			String revision = rule.revision();
			scans.put(rule.id(), revision == null ? List.of() : records.maps("SELECT m.scanType AS scan_type,"
					+ "m.scanId AS scan_id FROM RuleMetricScanEntity m WHERE m.ruleId=?1 AND m.revision=?2 AND"
					+ " m.bucketStart>=?3 AND m.findings>0 ORDER BY m.bucketStart DESC,m.scanId DESC",
					0, REPORTS_PER_RULE, rule.id(), revision, since));
		}
		List<Map<String, Object>> allScans = scans.values().stream().flatMap(List::stream).toList();
		Map<Long, String> tickets = uploadTickets(allScans);
		Set<Long> repositoryScans = existingScans(allScans, "repository", "RepoScanEntity");
		Set<Long> pullRequestScans = existingScans(allScans, "pull_request", "PullRequestScanEntity");
		Map<Long, List<Link>> links = new LinkedHashMap<>();
		for (RuleRef rule : rules) {
			List<Link> ruleLinks = new ArrayList<>();
			for (var scan : scans.get(rule.id())) {
				Long scanId = (Long) scan.get("scan_id");
				// The metrics outlive the scan they came from: a deleted scan has no report to open.
				boolean gone = switch ((String) scan.get("scan_type")) {
					case "repository" -> !repositoryScans.contains(scanId);
					case "pull_request" -> !pullRequestScans.contains(scanId);
					default -> false;
				};
				String report = gone ? null : reportUrl((String) scan.get("scan_type"), scanId, tickets);
				if (report != null) {
					String label = scan.get("scan_type").toString().replace('_', ' ') + " scan " + scan.get("scan_id");
					// Full encoding: a rule named "C++ …" must not arrive as "C  …".
					ruleLinks.add(new Link(label,
							report + "?reviewSearch=" + UriUtils.encode(rule.name(), StandardCharsets.UTF_8)));
				}
			}
			links.put(rule.id(), ruleLinks);
		}
		return links;
	}

	/** The ids of this type's scans that still exist; the metrics keep the ids of scans deleted since. */
	private Set<Long> existingScans(List<Map<String, Object>> scans, String scanType, String entity) {
		List<Long> ids = scans.stream().filter(scan -> scanType.equals(scan.get("scan_type")))
				.map(scan -> (Long) scan.get("scan_id")).distinct().toList();
		Set<Long> existing = new HashSet<>();
		if (!ids.isEmpty()) {
			for (var row : records.maps("SELECT s.id AS id FROM " + entity + " s WHERE s.id IN ?1", 0, ids.size(), ids)) {
				existing.add((Long) row.get("id"));
			}
		}
		return existing;
	}

	/** Upload reports are addressed by ticket, not scan id. */
	private Map<Long, String> uploadTickets(List<Map<String, Object>> scans) {
		List<Long> uploadIds = scans.stream().filter(scan -> "upload".equals(scan.get("scan_type")))
				.map(scan -> (Long) scan.get("scan_id")).distinct().toList();
		Map<Long, String> tickets = new LinkedHashMap<>();
		if (!uploadIds.isEmpty()) {
			for (var row : records.maps("SELECT s.id AS id,s.container.ticket AS ticket FROM UploadScanEntity s"
					+ " WHERE s.id IN ?1", 0, uploadIds.size(), uploadIds)) {
				if (row.get("ticket") instanceof String ticket && !ticket.isBlank()) {
					tickets.put((Long) row.get("id"), ticket);
				}
			}
		}
		return tickets;
	}

	private static String reportUrl(String scanType, Long scanId, Map<Long, String> tickets) {
		return switch (scanType) {
			case "pull_request" -> "/scan/report/" + scanId;
			case "repository" -> "/reposcan/report/" + scanId;
			case "upload" -> tickets.containsKey(scanId)
					? "/uploadscan/report/" + UriUtils.encodePathSegment(tickets.get(scanId), StandardCharsets.UTF_8)
					: null;
			default -> null;
		};
	}
}

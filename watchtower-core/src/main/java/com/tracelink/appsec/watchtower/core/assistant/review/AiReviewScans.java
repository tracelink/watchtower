package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.hibernate.Hibernate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.tracelink.appsec.watchtower.core.assistant.AssistantSecretFindings;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingLocator;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * Where an AI review reads from: the repository and commit a pull request or repository scan was made at, the files
 * a person can choose from, and the scanner findings the review's answers are compared with. Secret findings are
 * left out everywhere, since they are never sent and never shown.
 */
@Component
public class AiReviewScans {
	/** More findings than this in one scan are not compared, so the comparison says "not checked" instead of guessing. */
	static final int MAX_FINDINGS = 5000;
	static final int MAX_CANDIDATES = 200;
	/** How many source files of a commit are listed before the ones with findings are put first. */
	static final int MAX_TREE_FILES = 5000;
	private static final Logger LOG = LoggerFactory.getLogger(AiReviewScans.class);
	/** A commit as a scan recorded it: Bitbucket Cloud records a pull request's as a 12-character prefix. */
	private static final Pattern COMMIT = Pattern.compile("[a-f0-9]{7,40}");
	private static final Pattern FULL_COMMIT = Pattern.compile("[a-f0-9]{40}");
	/** Source files worth reading; images, archives, lock files and the like are not offered. */
	private static final Set<String> CODE = Set.of("java", "kt", "scala", "groovy", "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "rb",
			"php", "cs", "c", "cc", "cpp", "h", "hpp", "rs", "swift", "vue", "sh", "sql", "html", "xml", "yaml", "yml", "json", "tf");

	/** A scan, resolved. {@code pullRequest} is null for a repository scan. */
	public record Scan(String type, long id, RepositoryEntity repository, String commit, PullRequest pullRequest) {
	}

	/** A scanner finding of the scan: only where and which rule, never a message or code. */
	public record Point(String path, int line, String rule) {
	}

	/** The scan's findings, and whether the list is all of them. */
	public record Points(List<Point> points, boolean complete) {
	}

	/** A file a person can pick. */
	public record Candidate(String path, int findings, boolean changed) {
	}

	private final LedgerRepository records;
	private final RepoScanRepository repoScans;
	private final RepoScanReportService reports;
	private final FindingLocator locator;
	private final AssistantSecretFindings secrets;
	private final AssistantSourceTools source;

	public AiReviewScans(LedgerRepository records, RepoScanRepository repoScans, RepoScanReportService reports, FindingLocator locator,
			AssistantSecretFindings secrets, AssistantSourceTools source) {
		this.records = records;
		this.repoScans = repoScans;
		this.reports = reports;
		this.locator = locator;
		this.secrets = secrets;
		this.source = source;
	}

	/** The scan's repository and pinned commit, or a plain reason it cannot be reviewed. */
	@Transactional(readOnly = true)
	public Scan resolve(String scanType, long scanId) {
		if (scanId <= 0) {
			throw new IllegalArgumentException("Choose a scan.");
		}
		Scan scan = switch (scanType == null ? "" : scanType) {
			case "pull_request" -> pullRequestScan(scanId);
			case "repository" -> repositoryScan(scanId);
			default -> throw new IllegalArgumentException("Only pull request and repository scans can be reviewed.");
		};
		if (scan.repository() == null) {
			throw new IllegalArgumentException("The repository is not in Watchtower's catalog, so its source cannot be read.");
		}
		if (scan.commit() == null || !COMMIT.matcher(scan.commit()).matches()) {
			throw new IllegalArgumentException("The scanned commit was not recorded for this scan.");
		}
		return scan;
	}

	/**
	 * The same scan with its commit as a full hash, which is what reading the exact source needs. A short recorded
	 * commit is completed by the source control system; if that cannot be done the reason is plain.
	 */
	public Scan pinned(String owner, Scan scan) {
		if (FULL_COMMIT.matcher(scan.commit()).matches()) {
			return scan;
		}
		try {
			String full = source.target(owner, scan.repository().getId()).api().fullCommit(scan.repository().getRepoName(), scan.commit());
			return new Scan(scan.type(), scan.id(), scan.repository(), full.toLowerCase(Locale.ROOT), scan.pullRequest());
		} catch (java.io.IOException e) {
			LOG.warn("Could not complete the commit {} of {} scan {} to a full hash: {}", scan.commit(), scan.type(), scan.id(), e.getMessage());
			throw new IllegalArgumentException("The scanned commit could not be completed to a full hash by the source control system, so its files cannot be read.");
		}
	}

	private Scan pullRequestScan(long scanId) {
		PullRequestScanEntity scan = records.find(PullRequestScanEntity.class, scanId);
		if (scan == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown scan");
		}
		var container = scan.getContainer();
		PullRequest pr = container.toPullRequest();
		// The changed files are those of the commit that was scanned, not of a later push.
		pr.setCommitHash(scan.getCommitHash());
		return new Scan("pull_request", scanId, locator.catalogRepository(container.getApiLabel(), container.getRepoName()),
				scan.getCommitHash(), pr);
	}

	private Scan repositoryScan(long scanId) {
		var scan = repoScans.findById(scanId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown scan"));
		// The scan holds a lazy stand-in; the background job reads the repository after this transaction has ended.
		return new Scan("repository", scanId, (RepositoryEntity) Hibernate.unproxy(scan.getRepository()), scan.getCommitHash(), null);
	}

	/** The scan's scanner findings with secret ones removed. */
	@Transactional(readOnly = true)
	public Points findings(Scan scan) {
		var secret = secrets.secretRules();
		List<Point> points = new ArrayList<>();
		if (scan.pullRequest() != null) {
			var rows = records.maps("SELECT v.fileName AS file,v.lineNum AS line,v.violationName AS rule,v.ruleIdentity.module AS module,v.ruleIdentity.ruleId AS rule_id "
					+ "FROM PullRequestViolationEntity v WHERE v.scan.id=?1", 0, MAX_FINDINGS + 1, scan.id());
			for (var row : rows.subList(0, Math.min(rows.size(), MAX_FINDINGS))) {
				Long ruleId = row.get("rule_id") instanceof Number n ? n.longValue() : null;
				if (!secret.contains(ruleId, (String) row.get("module"), (String) row.get("rule"))) {
					points.add(new Point(String.valueOf(row.get("file")), row.get("line") instanceof Number n ? n.intValue() : 0, String.valueOf(row.get("rule"))));
				}
			}
			return new Points(List.copyOf(points), rows.size() <= MAX_FINDINGS);
		}
		var repoScan = repoScans.findById(scan.id()).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown scan"));
		var report = reports.getReport(repoScan).orElse(null);
		if (report == null) {
			return new Points(List.of(), false);
		}
		for (var finding : report.findings()) {
			var identity = finding.ruleIdentity();
			boolean isSecret = Boolean.TRUE.equals(finding.sensitive())
					|| secret.contains(identity == null ? null : identity.ruleId(), identity == null ? null : identity.module(), finding.rule());
			if (!isSecret) {
				points.add(new Point(finding.file(), finding.line(), finding.rule()));
			}
		}
		return new Points(List.copyOf(points), report.findings().size() >= report.totalFindings());
	}

	/**
	 * The files to choose from: a pull request's changed files, or the source files of a repository scan's commit.
	 * Files with the most findings come first. The source control system is asked live in both cases.
	 */
	public List<Candidate> candidates(String owner, Scan scan) {
		Map<String, int[]> counts = new LinkedHashMap<>();
		for (Point point : findings(scan).points()) {
			counts.computeIfAbsent(normalize(point.path()), k -> new int[1])[0]++;
		}
		Set<String> changed = new HashSet<>();
		if (scan.pullRequest() != null) {
			var target = source.target(owner, scan.repository().getId());
			for (String path : target.api().getChangedFilesForPullRequest(scan.pullRequest()).keySet()) {
				String key = normalize(path);
				changed.add(key);
				counts.computeIfAbsent(key, k -> new int[1]);
			}
		} else {
			addSourceFiles(owner, scan, counts);
		}
		return counts.entrySet().stream().filter(e -> reviewable(e.getKey()))
				.map(e -> new Candidate(e.getKey(), e.getValue()[0], changed.contains(e.getKey())))
				.sorted(Comparator.comparingInt(Candidate::findings).reversed().thenComparing(Candidate::path)).limit(MAX_CANDIDATES).toList();
	}

	/**
	 * A repository scan can be reviewed in any source file at the scanned commit, not only those with findings. If the
	 * commit cannot be downloaded the files with findings are still offered; with none of those, the reason is shown.
	 */
	private void addSourceFiles(String owner, Scan scan, Map<String, int[]> counts) {
		try {
			for (String path : source.sourceFiles(owner, scan.repository(), scan.commit(), AiReviewScans::reviewable, MAX_TREE_FILES)) {
				counts.computeIfAbsent(normalize(path), k -> new int[1]);
			}
		} catch (IllegalArgumentException e) {
			if (counts.isEmpty()) {
				throw e;
			}
			LOG.warn("Source files of repository scan {} could not be listed, so only files with findings are offered: {}", scan.id(), e.getMessage());
		}
	}

	/** Repository-relative with forward slashes and no leading slash, so spellings of one path compare equal. */
	public static String normalize(String path) {
		if (path == null) {
			return "";
		}
		String clean = path.replace('\\', '/');
		while (clean.startsWith("./") || clean.startsWith("/")) {
			clean = clean.startsWith("./") ? clean.substring(2) : clean.substring(1);
		}
		return clean;
	}

	/** Whether two paths name the same file; one may carry a leading folder the other lacks. */
	public static boolean samePath(String a, String b) {
		String x = normalize(a), y = normalize(b);
		return !x.isEmpty() && !y.isEmpty() && (x.equals(y) || x.endsWith("/" + y) || y.endsWith("/" + x));
	}

	/** A plain, short, repository-relative path to a kind of file worth reading. */
	public static boolean reviewable(String path) {
		String clean = normalize(path);
		if (clean.isEmpty() || clean.length() > 255 || clean.indexOf('\0') >= 0 || clean.contains("..") || clean.contains(":")
				|| clean.endsWith("/") || clean.contains("//") || clean.endsWith(".min.js")) {
			return false;
		}
		int dot = clean.lastIndexOf('.');
		// A name before the dot is required, so ".java" alone is not a source file.
		return dot > clean.lastIndexOf('/') + 1 && CODE.contains(clean.substring(dot + 1).toLowerCase(Locale.ROOT));
	}
}

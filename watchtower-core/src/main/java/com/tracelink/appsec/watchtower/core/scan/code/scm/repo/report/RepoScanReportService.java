package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;

/**
 * Reads stored repository scan reports for viewing and export, and shows a file's code around
 * its findings, as the pull request report does, by fetching it from the SCM at the scanned
 * commit. The code is never stored or cached; a secrets scanner's line is always masked.
 * Parsed reports (which hold no code) are kept in a small cache, since a report page and its
 * exports read the same report several times.
 *
 * @author Watchtower
 */
@Service
public class RepoScanReportService {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanReportService.class);

	static final int CACHE_SIZE = 16;

	private final RepoReportStore store;

	private final ApiIntegrationService integrations;

	private final RuleService rules;

	private final ScanRegistrationService registry;

	private final Map<String, RepoScanReport> cache = Collections.synchronizedMap(
			new LinkedHashMap<>(CACHE_SIZE, 0.75f, true) {
				private static final long serialVersionUID = 1L;

				@Override
				protected boolean removeEldestEntry(Map.Entry<String, RepoScanReport> eldest) {
					return size() > CACHE_SIZE;
				}
			});

	@Autowired
	public RepoScanReportService(RepoReportStore store, ApiIntegrationService integrations,
			RuleService rules, ScanRegistrationService registry) {
		this.store = store;
		this.integrations = integrations;
		this.rules = rules;
		this.registry = registry;
	}

	/**
	 * @param scan a finished scan
	 * @return its report, or empty if it has none or the report has expired
	 */
	public Optional<RepoScanReport> getReport(RepoScanEntity scan) {
		String key = scan.getReportKey();
		if (key == null) {
			return Optional.empty();
		}
		RepoScanReport cached = cache.get(key);
		if (cached != null) {
			return Optional.of(cached);
		}
		try {
			Optional<RepoScanReport> report = store.get(key).map(bytes -> {
				try {
					return RepoReportCodec.decode(bytes).interpreted();
				} catch (IOException e) {
					LOG.warn("Unreadable report {}", key);
					return null;
				}
			});
			report.ifPresent(r -> cache.put(key, r));
			return report;
		} catch (IOException e) {
			LOG.error("Could not read report " + key, e);
			return Optional.empty();
		}
	}

	/**
	 * @return a link to the file at the scanned commit in the SCM, or null
	 */
	public String fileLink(RepoScanEntity scan, String file, int line) {
		ApiIntegrationEntity integration =
				integrations.findByLabel(scan.getRepository().getApiLabel());
		return integration instanceof AbstractScmIntegrationEntity scm
				? scm.makeFileLink(scan.getRepository().getRepoName(), scan.getCommitHash(), file,
						line)
				: null;
	}

	/**
	 * @param report a report
	 * @return the files its listed findings are in, with how many each has, in path order: the
	 *         report's Code section, whose code loads per file when opened
	 */
	public List<CodeFile> codeFiles(RepoScanReport report) {
		return report.findings().stream().filter(f -> isPlainPath(f.file()))
				.collect(Collectors.groupingBy(RepoScanReport.Finding::file, TreeMap::new,
						Collectors.counting()))
				.entrySet().stream().map(e -> new CodeFile(e.getKey(), e.getValue().intValue()))
				.toList();
	}

	/**
	 * One file's code, as the pull request report shows it: a window around each flagged line,
	 * flagged lines highlighted, a secret's line masked and given no context. Fetched from the
	 * SCM at the scanned commit, in memory, for this response only.
	 *
	 * @param scan   the scan
	 * @param report its report
	 * @param file   a file the report's findings are in
	 * @return the file to render; without source if the SCM did not return it
	 */
	public PRScanResultFile codeFile(RepoScanEntity scan, RepoScanReport report, String file) {
		List<RepoScanReport.Finding> findings = report.findings().stream()
				.filter(f -> f.file().equals(file)).toList();
		Map<Boolean, Set<Integer>> linesBySensitivity = findings.stream()
				.collect(Collectors.partitioningBy(this::isSensitive, Collectors.mapping(
						RepoScanReport.Finding::line, Collectors.toSet())));
		return CodeExcerpts.of(file, content(scan, file), linesBySensitivity.get(false),
				linesBySensitivity.get(true), findings.size());
	}

	/**
	 * @return true if the finding's line must never be shown: as recorded at scan time, or for
	 *         a report from before that was recorded, as its rule says
	 */
	boolean isSensitive(RepoScanReport.Finding finding) {
		return finding.sensitive() != null ? finding.sensitive() : isSensitive(finding.rule());
	}

	private FileFetch content(RepoScanEntity scan, String file) {
		if (StringUtils.isBlank(scan.getCommitHash())) {
			return FileFetch.unavailable("This scan did not record which commit it read, so the file"
					+ " cannot be fetched.");
		}
		if (!isPlainPath(file)) {
			return FileFetch.unavailable("The file's path is not one Watchtower will request from the"
					+ " source control server.");
		}
		ApiIntegrationEntity integration =
				integrations.findByLabel(scan.getRepository().getApiLabel());
		if (integration == null || !(integration.createApi() instanceof IScmApi api)) {
			return FileFetch.unavailable("The source control integration \""
					+ scan.getRepository().getApiLabel() + "\" is no longer configured in Watchtower.");
		}
		FileFetch fetched = api.fetchFileAtCommit(scan.getRepository().getRepoName(),
				scan.getCommitHash(), file);
		return fetched != null ? fetched : FileFetch.unavailable(null);
	}

	/**
	 * A repository-relative path that cannot change which SCM resource is fetched: no parent
	 * segments, query, fragment, leading slash or control characters.
	 */
	static boolean isPlainPath(String file) {
		return StringUtils.isNotBlank(file) && !file.startsWith("/") && !file.contains("?")
				&& !file.contains("#") && !file.contains("\\")
				&& file.chars().noneMatch(Character::isISOControl)
				&& Arrays.stream(file.split("/")).noneMatch(".."::equals);
	}

	/**
	 * @param rule a rule name
	 * @return true if the rule belongs to a scanner whose findings are secrets
	 */
	public boolean isSensitive(String rule) {
		RuleEntity entity = rules.getRule(rule);
		if (entity == null) {
			// Unknown rule: cannot tell, so do not show code
			return true;
		}
		RuleDto dto = entity.toDto();
		return dto == null || registry.isSensitiveModule(dto.getModule());
	}

	/**
	 * A file of the report's Code section, before its code is loaded.
	 *
	 * @param name         the path
	 * @param findingCount how many listed findings it has
	 */
	public record CodeFile(String name, int findingCount) {
	}
}

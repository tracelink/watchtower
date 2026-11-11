package com.tracelink.appsec.watchtower.core.rest.scan.repo;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService.PlanRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Repository scans for automation: start a scan of named repositories, then poll the run or a
 * scan for its status and severity counts. Results never include code.
 *
 * @author Watchtower
 */
@RestController
@RequestMapping("/rest/reposcan")
public class RepoScanRestController {

	private final RepoScanService scans;

	private final RepoScanRepository rows;

	public RepoScanRestController(RepoScanService scans, RepoScanRepository rows) {
		this.scans = scans;
		this.rows = rows;
	}

	/**
	 * What to scan, as sent by a client.
	 *
	 * @param apiLabel  the SCM integration
	 * @param repos     repository names or patterns
	 * @param branches  blank for each default branch, else names or patterns
	 * @param rulesetId null for each repository's own ruleset
	 */
	public record ScanRequest(String apiLabel, List<String> repos, String branches,
			Long rulesetId) {
	}

	@PostMapping
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
	public ResponseEntity<Map<String, Object>> scan(@RequestBody ScanRequest request,
			Principal user) {
		try {
			RepoScanPlanEntity plan = scans.submit(new PlanRequest("API scan", request.apiLabel(),
					request.repos() == null ? "" : String.join("\n", request.repos()),
					request.branches(), request.rulesetId(), PlanFrequency.ONCE, null, null,
					null), user.getName());
			return ResponseEntity.accepted().body(Map.of("planId", plan.getId(), "runNo", 1,
					"status", "/rest/reposcan/run/" + plan.getId() + "/1"));
		} catch (IllegalArgumentException e) {
			return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
		}
	}

	@GetMapping("/{scanId}")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
	public ResponseEntity<ScanSummary> scanStatus(@PathVariable long scanId) {
		return rows.findWithRepository(scanId).map(ScanSummary::of).map(ResponseEntity::ok)
				.orElse(ResponseEntity.notFound().build());
	}

	@GetMapping("/run/{planId}/{runNo}")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
	public List<ScanSummary> runStatus(@PathVariable long planId, @PathVariable int runNo) {
		return rows.findRun(planId, runNo).stream().map(ScanSummary::of).toList();
	}

	/**
	 * One scan's status and counts.
	 */
	public record ScanSummary(long scanId, String repository, String branch, String commit,
			String status, String outcome, int findings, Map<String, Integer> bySeverity,
			Integer newFindings, Integer fixedFindings, String error) {

		static ScanSummary of(RepoScanEntity scan) {
			Map<String, Integer> bySeverity = new LinkedHashMap<>();
			scan.getSeverityCounts().levels()
					.forEach(level -> bySeverity.put(level.name(), level.count()));
			return new ScanSummary(scan.getId(), scan.getRepository().getRepoName(),
					scan.getBranch(), scan.getCommitHash(), scan.getStatus().getDisplayName(),
					scan.getOutcome() == null ? null : scan.getOutcome().name(),
					scan.getFindingCount(), bySeverity, scan.getNewCount(), scan.getFixedCount(),
					scan.getError());
		}
	}
}

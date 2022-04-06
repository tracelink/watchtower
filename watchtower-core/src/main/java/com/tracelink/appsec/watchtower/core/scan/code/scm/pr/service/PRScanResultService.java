package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.scm.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;

/**
 * Handles logic around storing a retrieving scan results
 *
 * @author csmith
 */
@Service
public class PRScanResultService
		extends AbstractScanResultService<PullRequestScanEntity, PullRequestViolationEntity> {
	private static Logger LOG = LoggerFactory.getLogger(PRScanResultService.class);

	private PRContainerRepository prRepo;

	private RepositoryRepository repoRepo;

	private PRScanRepository scanRepo;

	private PRViolationRepository vioRepo;

	private RuleService ruleService;

	private APIIntegrationService apiIntegrationService;

	public PRScanResultService(
			@Autowired PRContainerRepository prRepo, @Autowired RepositoryRepository repoRepo,
			@Autowired PRScanRepository scanRepo, @Autowired PRViolationRepository vioRepo,
			@Autowired RuleService ruleService,
			@Autowired APIIntegrationService apiIntegrationService) {
		super(scanRepo, vioRepo);
		this.prRepo = prRepo;
		this.repoRepo = repoRepo;
		this.scanRepo = scanRepo;
		this.vioRepo = vioRepo;
		this.ruleService = ruleService;
		this.apiIntegrationService = apiIntegrationService;
	}

	/**
	 * Store a PR Scan to a backend database
	 *
	 * @param pr         the Pull Request to save
	 * @param startTime  the starting time of the scan
	 * @param violations the violations found in this scan
	 * @param errors     the errors found in this scan
	 */
	public void savePullRequestScan(PullRequest pr, long startTime,
			List<PullRequestViolationEntity> violations, List<CodeScanError> errors) {
		if (violations == null) {
			return;
		}
		long now = System.currentTimeMillis();

		PullRequestContainerEntity prEntity =
				prRepo.findOneByApiLabelAndRepoNameAndPrId(pr.getApiLabel(),
						pr.getRepoName(), pr.getPrId());
		if (prEntity == null) {
			prEntity = new PullRequestContainerEntity(pr);
			prEntity = prRepo.saveAndFlush(prEntity);
		}

		// no new, unblocked issues means resolved
		boolean resolved = pr.getState().equals(PullRequestState.DECLINED)
				|| violations.stream().noneMatch(v -> v.isNewViolation());

		prEntity.setResolved(resolved);
		prEntity.setLastReviewedDate(now);
		PullRequestContainerEntity savedPREntity = prRepo.saveAndFlush(prEntity);

		PullRequestScanEntity scanEntity = new PullRequestScanEntity();
		scanEntity.setContainer(savedPREntity);
		scanEntity.setEndDate(now);
		scanEntity.setSubmitDate(pr.getSubmitTime());
		scanEntity.setStartDate(startTime);
		scanEntity.setStatus(ScanStatus.DONE);
		if (!errors.isEmpty()) {
			scanEntity.setError(errors.stream().map(CodeScanError::getErrorMessage)
					.collect(Collectors.joining(", ")));
		}
		PullRequestScanEntity savedScanEntity = scanRepo.saveAndFlush(scanEntity);

		violations.forEach(v -> {
			v.setScan(savedScanEntity);
			vioRepo.save(v);
		});
		vioRepo.flush();
	}

	/**
	 * Given a {@linkplain PullRequest}, mark it as having been newly reviewed and now resolved.
	 * 
	 * @param pr the {@linkplain PullRequest} to resolve
	 */
	public void markPrResolved(PullRequest pr) {
		long now = System.currentTimeMillis();

		PullRequestContainerEntity prEntity =
				prRepo.findOneByApiLabelAndRepoNameAndPrId(pr.getApiLabel(),
						pr.getRepoName(), pr.getPrId());

		if (prEntity == null) {
			LOG.error(
					"Request made to resolve a PR that hasn't been scanned yet (" + pr.getPRString()
							+ "). Creating and marking resolved anyway.");
			prEntity = new PullRequestContainerEntity(pr);
		}

		prEntity.setResolved(true);
		prEntity.setLastReviewedDate(now);
		prRepo.saveAndFlush(prEntity);
	}


	/**
	 * Counts the number of repositories that have been scanned
	 *
	 * @return number of repositories scanned
	 */
	public long countRepos() {
		return repoRepo.count();
	}

	/**
	 * Counts the number of pull requests that have been scanned
	 *
	 * @return number of pull requests scanned
	 */
	public long countPrs() {
		return this.prRepo.count();
	}

	private PRScanResult generateScanResultForScan(PullRequestScanEntity scanEntity) {
		PullRequestContainerEntity container = scanEntity.getContainer();
		String repo = container.getRepoName();
		String id = container.getPrId();

		APIIntegrationEntity entity = apiIntegrationService.findByLabel(container.getApiLabel());

		PRScanResult result = new PRScanResult();
		result.setId(scanEntity.getId());
		result.setDisplayName(repo + "-" + id);
		result.setAuthor(container.getAuthor());
		result.setDate(scanEntity.getEndDate());
		result.setPrLink(entity == null ? "" : entity.makePRLink(repo, id));
		result.setApiLabel(container.getApiLabel());
		result.setRepoName(repo);
		result.setPrId(id);
		result.setViolations(
				scanEntity.getViolations().stream().map(this::generateResultForViolation)
						.collect(Collectors.toList()));
		return result;
	}

	private PRScanResultViolation generateResultForViolation(PullRequestViolationEntity violation) {
		PRScanResultViolation result = new PRScanResultViolation();
		result.setFileName(violation.getFileName());
		result.setLineNumber(violation.getLineNum());
		result.setSeverity(violation.getSeverity());
		result.setSeverityValue(violation.getSeverityValue());
		result.setViolationName(violation.getViolationName());

		String message = "Rule guidance not found";
		RuleEntity rule = ruleService.getRule(violation.getViolationName());
		if (rule != null) {
			message = rule.getMessage();
		}
		result.setMessage(message);

		return result;
	}

	/**
	 * Get a list of {@linkplain PRScanResult} based on the given filter and return the given page
	 * number's worth of data
	 * 
	 * @param filter   the filter to divy-up the results
	 * @param pageSize the number of results to return
	 * @param pageNum  the pagenumber of results to return
	 * @return a list of size {@code pageSize} containing results using the {@code filter} on page
	 *         {@code pageNum}
	 */
	public List<PRScanResult> getScanResultsWithFilters(PRResultFilter filter, int pageSize,
			int pageNum) {
		List<PRScanResult> results;
		switch (filter) {
			case ALL:
				results =
						scanRepo.findAll(
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate")))
								.stream().map(this::generateScanResultForScan)
								.collect(Collectors.toList());
				break;
			case UNRESOLVED:
				results = prRepo
						.findByResolvedFalse(
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "lastReviewedDate")))
						.stream()
						.map(container -> container.getScans().get(0))
						.map(this::generateScanResultForScan)
						.collect(Collectors.toList());
				break;
			case VIOLATIONS:
				results = vioRepo
						.findAllGroupByScan(
								PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "scan")))
						.stream()
						.map(this::generateScanResultForScan)
						.collect(Collectors.toList());
				break;
			default:
				LOG.error("Filter is not configured to get PRs");
				throw new IllegalArgumentException("Filter is not configured to get PRs");
		}
		return results;
	}

	/**
	 * Get an individual result for a scan id
	 * 
	 * @param scanId the id of the scan to get results for
	 * @return the result of the scan, or null if not found
	 */
	public PRScanResult getScanResultForScanId(String scanId) {
		Optional<PullRequestScanEntity> entity = scanRepo.findById(Long.valueOf(scanId));
		return entity.isPresent() ? generateScanResultForScan(entity.get()) : null;
	}

	/**
	 * Get a pull request by label, repo, and id
	 * 
	 * @param apiLabel the label of the api
	 * @param repo     the repository
	 * @param prid     the pull request id
	 * @return the pull request container, or null
	 */
	public PullRequestContainerEntity getPullRequestByLabelRepoAndId(String apiLabel, String repo,
			String prid) {
		return prRepo.findOneByApiLabelAndRepoNameAndPrId(apiLabel, repo, prid);
	}

}

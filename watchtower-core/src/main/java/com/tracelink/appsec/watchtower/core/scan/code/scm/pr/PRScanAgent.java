package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

/**
 * Handles scanning via SCM. downloads files from SCM and also processes violations by checking if a
 * violation is new
 *
 * @author csmith, mcool
 */
public class PRScanAgent extends
		AbstractCodeScanAgent<PRScanAgent> {
	private static Logger LOG = LoggerFactory.getLogger(PRScanAgent.class);
	private static final String SEP = "  \n";

	private PullRequest pullRequest;
	private long startTime;

	private IScmApi api;
	private PRScanResultService prScanResultService;

	public PRScanAgent(PullRequest pullRequest) {
		super(pullRequest.getPRString());
		this.pullRequest = pullRequest;
	}

	/**
	 * Set the {@linkplain IScmApi} for this Agent's configuration to interact with Pull Request
	 * SCMs
	 * 
	 * @param api the api to use
	 * @return this agent
	 */
	public PRScanAgent withApi(IScmApi api) {
		this.api = api;
		return this;
	}


	/**
	 * Set the {@linkplain PRScanResultService} for this Agent's configuration
	 * 
	 * @param prScanResultService the result Service to use
	 * @return this agent
	 */
	public PRScanAgent withScanResultService(PRScanResultService prScanResultService) {
		this.prScanResultService = prScanResultService;
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		this.startTime = System.currentTimeMillis();
		if (api == null) {
			throw new ScanInitializationException(
					"API must be configured.");
		}

		if (prScanResultService == null) {
			throw new ScanInitializationException(
					"Results Service must be configured.");
		}

		// Test connection to the file source
		if (!api.testConnectionForPullRequest(pullRequest)) {
			throw new ScanInitializationException(
					"Connection to SCM failed for scan: " + getScanName());
		}
		collectFiles();
	}


	/**
	 * {@inheritDoc}
	 * <p>
	 * The implementation of report for SCM is to create database artifacts of this scan, identify
	 * if any violations are new or are blocking, and send a report to the attached SCM before
	 * saving all results
	 */
	@Override
	protected void report(List<CodeScanReport> reports) {
		List<PullRequestViolationEntity> violations = new ArrayList<>();
		List<CodeScanError> errors = new ArrayList<CodeScanError>();
		for (CodeScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				PullRequestViolationEntity ve =
						new PullRequestViolationEntity(sv, getWorkingDirectory());
				RulesetDto ruleset = getRuleset();
				if (ruleset.getBlockingLevel() != null) {
					ve.setBlocking(RulePriority.valueOf(sv.getSeverityValue())
							.compareTo(ruleset.getBlockingLevel()) <= 0);
				}
				violations.add(ve);
			});
			errors.addAll(report.getErrors());
		}

		// Identify violations that are new
		identifyNewViolations(violations);

		Collections.sort(violations);

		reportToSCM(violations, errors);

		try {
			// re-get the pr so that it has fresh data
			PullRequest updated = api.updatePRData(pullRequest);
			prScanResultService.savePullRequestScan(updated, this.startTime, violations, errors);
		} catch (ScanRejectedException e) {
			LOG.error("Could not save Pull Request Scan due to exception", e);
		}
	}

	@Override
	protected void clean() {
		FileUtils.deleteQuietly(getWorkingDirectory().toFile());
	}

	private static Set<String> UNINTERESTING_FOLDERS =
			Stream.of("test", "node_modules").collect(Collectors.toSet());
	private static Set<String> UNINTERESTING_FILE_TYPES =
			Stream.of("jar", "png", "jpg").collect(Collectors.toSet());

	/**
	 * Gather all needed files and copy them into the target directory
	 * 
	 * @throws ScanInitializationException if there are no files to scan
	 */
	private void collectFiles() throws ScanInitializationException {
		try {
			api.downloadSourceForPullRequest(pullRequest, getWorkingDirectory());
			Files.walkFileTree(getWorkingDirectory(), new FileVisitor<Path>() {
				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
						throws IOException {
					if (UNINTERESTING_FOLDERS.contains(dir.getFileName().toString())) {
						FileUtils.deleteQuietly(dir.toFile());
						return FileVisitResult.SKIP_SUBTREE;
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					if (UNINTERESTING_FILE_TYPES
							.contains(FilenameUtils.getExtension(file.getFileName().toString()))) {
						FileUtils.deleteQuietly(file.toFile());
						return FileVisitResult.SKIP_SUBTREE;
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path file, IOException exc)
						throws IOException {
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc)
						throws IOException {
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (IOException e) {
			throw new ScanInitializationException("Could not download source", e);
		}
	}

	/**
	 * For each violation in the given list, determine if the violation is preexisting or new for
	 * this scan. Return the results of this determination.
	 *
	 * @param violations the violations to mark as new or preexisting
	 */
	private void identifyNewViolations(
			List<PullRequestViolationEntity> violations) {
		// Get set of files with violations
		Set<String> violationFiles = new HashSet<>();
		violations.forEach(v -> violationFiles.add(v.getFileName()));

		// Get diff file for each file with violations
		Map<String, DiffFile> diffFiles = new HashMap<>();
		violationFiles.forEach(f -> {
			DiffFile diff = api.getGitDiffFile(pullRequest, f);
			if (diff.hasDiffs()) {
				diffFiles.put(f, diff);
			}
		});

		// Use the diff files to determine if each violation is new or preexisting
		Iterator<PullRequestViolationEntity> violationIter = violations.iterator();
		while (violationIter.hasNext()) {
			PullRequestViolationEntity violation = violationIter.next();
			// We are only looking for violations that occur in files that have been modified. So
			// remove all latent violations in source code files that have nothing to do with this
			// Pull Request
			if (!diffFiles.containsKey(violation.getFileName())) {
				violationIter.remove();
			} else {
				violation.setNewViolation(diffFiles.get(violation.getFileName())
						.isLineChanged(violation.getLineNum()));
			}
		}
	}

	/**
	 * send a comment, and then if this scan should block based on any findings, send the block
	 * command
	 * 
	 * @param violations the list of violations found in this scan from all scanners
	 * @param errors     the list of errors found during this scan
	 */
	private void reportToSCM(List<PullRequestViolationEntity> violations,
			List<CodeScanError> errors) {
		api.sendComment(pullRequest, buildReport(violations));

		if (hasBlockingViolations(violations)) {
			api.blockPR(pullRequest);
		}
		if (!errors.isEmpty()) {
			logErrors(errors);
		}
	}

	private String buildReport(List<PullRequestViolationEntity> violations) {
		// Report for new violations
		StringBuilder newViolationReport = new StringBuilder();

		// Report for preexisting violations
		StringBuilder existingViolationReport = new StringBuilder();

		int numNewViolations = 0;
		int numExistingViolations = 0;

		for (PullRequestViolationEntity v : violations) {
			if (v.isNewViolation()) {
				numNewViolations++;
				violationReport(newViolationReport, v, true);
			} else {
				numExistingViolations++;
				violationReport(existingViolationReport, v, false);
			}
		}

		return constructFinalMessage(newViolationReport, existingViolationReport, numNewViolations,
				numExistingViolations);
	}

	private String constructFinalMessage(StringBuilder diffVulns, StringBuilder fileVulns,
			int diffVulnsNum, int fileVulnsNum) {
		StringBuilder finalMessage = new StringBuilder();
		finalMessage.append("###Watchtower Security Report").append(SEP);

		if (diffVulnsNum + fileVulnsNum > 0) {
			finalMessage.append("Total Violations Found in this Pull Request: ")
					.append(diffVulnsNum + fileVulnsNum)
					.append(SEP);
		} else {
			finalMessage.append("No Violations Found.");
		}
		if (diffVulnsNum > 0) {
			finalMessage.append("#### Issues added in this Pull Request: ").append(diffVulnsNum)
					.append(SEP);
			finalMessage.append(diffVulns);
		}
		if (fileVulnsNum > 0) {
			finalMessage.append("#### Pre-existing issues in this Pull Request: ")
					.append(fileVulnsNum).append(SEP);
			finalMessage.append(fileVulns);
		}
		return finalMessage.toString();
	}

	private void violationReport(StringBuilder sb, PullRequestViolationEntity v, boolean canBlock) {
		sb.append(SEP);
		sb.append("Severity: ").append(v.getSeverity());
		if (canBlock && v.isBlocking()) {
			sb.append(" BLOCKING");
		}
		sb.append(SEP);
		sb.append("File: ").append(v.getFileName()).append(SEP);
		sb.append("Line: ").append(v.getLineNum()).append(SEP);
		sb.append("Description: ").append(v.getMessage()).append(SEP);
		sb.append(SEP);
	}

	/**
	 * If there are any errors, this method will execute. Default implementation is to log to the
	 * debug log
	 * 
	 * @param errors the list of errors to log
	 */
	private void logErrors(List<CodeScanError> errors) {
		StringBuilder sb = new StringBuilder();
		sb.append("Errors found during scan: " + pullRequest.getPRString() + '\n');
		for (CodeScanError err : errors) {
			sb.append("--" + err.getErrorMessage() + '\n');
		}
		LOG.debug(sb.toString());
	}

	private Boolean hasBlockingViolations(List<PullRequestViolationEntity> violations) {
		return violations.stream().anyMatch(v -> (v.isBlocking() && v.isNewViolation()));
	}

}

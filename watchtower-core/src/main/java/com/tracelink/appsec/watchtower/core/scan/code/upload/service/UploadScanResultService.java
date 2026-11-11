package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter;
import com.tracelink.appsec.watchtower.core.rule.RuleChange;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResultViolation;

/**
 * Handles logic around storing a retrieving scan results
 *
 * @author csmith
 */
@Service
public class UploadScanResultService
		extends AbstractScanResultService<UploadScanEntity, UploadViolationEntity> {
	private static Logger LOG = LoggerFactory.getLogger(UploadScanResultService.class);

	private UploadContainerRepository uploadRepo;

	private UploadScanRepository scanRepo;

	private UploadViolationRepository vioRepo;

	private RuleService ruleService;
 @Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter ruleMetrics;

	private MetricsProjectionWriter metricsProjectionWriter;

	@Autowired(required = false)
	void setMetricsProjectionWriter(MetricsProjectionWriter writer) {
		this.metricsProjectionWriter = writer;
	}

	public UploadScanResultService(@Autowired UploadContainerRepository uploadRepo,
			@Autowired UploadScanRepository scanRepo, @Autowired UploadViolationRepository vioRepo,
			@Autowired RuleService ruleService) {
		super(scanRepo, vioRepo);
		this.uploadRepo = uploadRepo;
		this.scanRepo = scanRepo;
		this.vioRepo = vioRepo;
		this.ruleService = ruleService;
	}

	/**
	 * Create an {@linkplain UploadScanContainerEntity} by assigning a new UUID ticket to the input
	 * {@linkplain UploadScan} and marking the scan {@linkplain ScanStatus#NOT_STARTED}
	 * 
	 * @param upload the {@linkplain UploadScan} configuration
	 * @return the new {@linkplain UploadScanContainerEntity} with an attached scan marked
	 *         {@linkplain ScanStatus#NOT_STARTED}
	 */
	public UploadScanContainerEntity makeNewScanEntity(UploadScan upload) {
		String ticket;
		do {
			ticket = UUID.randomUUID().toString();
		} while (findUploadScanByTicket(ticket) != null);

		UploadScanContainerEntity use = new UploadScanContainerEntity();
		use.setTicket(ticket);
		use.setRuleSet(upload.getRuleSetName());
		use.setName(upload.getName());
		use.setSubmitter(upload.getUser());
		use.setStorageKey(upload.getStorageKey());
		use = uploadRepo.saveAndFlush(use);

		UploadScanEntity scan = new UploadScanEntity();
		scan.setContainer(use);
		scan.setEndDate(0L);
		scan.setSubmitDate(upload.getSubmitDate());
		scan.setStatus(ScanStatus.NOT_STARTED);
		scanRepo.saveAndFlush(scan);

		// resave to get the relationship with the ScanEntity
		return uploadRepo.saveAndFlush(use);
	}

	/**
	 * Given a scan ticket, mark the attached scan {@linkplain ScanStatus#IN_PROGRESS}.
	 * 
	 * @param ticket the ticket for the scan
	 * @return the {@linkplain UploadScanContainerEntity} with its scan marked
	 *         {@linkplain ScanStatus#IN_PROGRESS} or null if the ticket does not match a Container
	 */
	public UploadScanContainerEntity markScanInProgress(String ticket) {
		UploadScanContainerEntity use = findUploadScanByTicket(ticket);
		if (use == null) {
			return null;
		}
		UploadScanEntity scan = use.getLatestUploadScan();
		scan.setStartDate(System.currentTimeMillis());
		scan.setStatus(ScanStatus.IN_PROGRESS);
		scanRepo.saveAndFlush(scan);

		return uploadRepo.saveAndFlush(use);
	}

	/**
	 * Given a scan ticket, mark the attached scan {@linkplain ScanStatus#FAILED}.
	 * 
	 * @param ticket  the ticket for the scan
	 * @param message the failure message for this scan
	 * @return the {@linkplain UploadScanContainerEntity} with its scan marked
	 *         {@linkplain ScanStatus#FAILED} or null if the ticket does not match a Container
	 */
	public UploadScanContainerEntity markScanFailed(String ticket, String message) {
		UploadScanContainerEntity use = findUploadScanByTicket(ticket);
		if (use == null) {
			return null;
		}
		UploadScanEntity scan = use.getLatestUploadScan();
		scan.setStatus(ScanStatus.FAILED);
		scan.setError(message);
		return uploadRepo.saveAndFlush(use);
	}

	/**
	 * Given a scan ticket, mark the attached scan {@linkplain ScanStatus#DONE} and attach all
	 * violations to the scan
	 * 
	 * @param ticket     the ticket for the scan
	 * @param violations the list of {@linkplain AbstractScanViolationEntity} to save against this
	 *                   scan
	 */
	public void saveFinalUploadScan(String ticket,
			List<UploadViolationEntity> violations) {
		saveFinalUploadScan(ticket, violations, null);
	}

	public void saveFinalUploadScan(String ticket, List<UploadViolationEntity> violations,
			ScanExecutionSummary summary) {
		long now = System.currentTimeMillis();

		UploadScanContainerEntity use = findUploadScanByTicket(ticket);
		if (use == null) {
			return;
		}
		use.setLastReviewedDate(now);
		use = uploadRepo.saveAndFlush(use);

		UploadScanEntity scan = use.getLatestUploadScan();
		scan.setEndDate(now);
		scan.setStatus(ScanStatus.DONE);
		applyExecutionSummary(scan, summary);
		UploadScanEntity savedScanEntity = scanRepo.saveAndFlush(scan);

		violations.forEach(v -> {
			v.setScan(savedScanEntity);
			vioRepo.save(v);
		});

		vioRepo.flush();
  if (ruleMetrics != null) {
   try {
    ruleMetrics.recordEntities("upload", savedScanEntity.getId(), savedScanEntity.getEndDateMillis(),
      com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec.decode(savedScanEntity.getExecutionSnapshotJson()), violations);
   } catch (RuntimeException e) {
    LOG.warn("Rule identity projection failed for upload scan {}", savedScanEntity.getId());
   }
  }
		if (metricsProjectionWriter != null) {
			try {
				metricsProjectionWriter.record("upload", savedScanEntity, violations);
			} catch (RuntimeException e) {
				metricsProjectionWriter.recordFailure("upload", e);
			}
		}
	}

	public void saveExecutionSummary(String ticket, ScanExecutionSummary summary) {
		UploadScanContainerEntity container = findUploadScanByTicket(ticket);
		if (container == null || summary == null) return;
		UploadScanEntity entity = container.getLatestUploadScan();
		applyExecutionSummary(entity, summary);
		scanRepo.saveAndFlush(entity);
	}

	private void applyExecutionSummary(UploadScanEntity entity, ScanExecutionSummary summary) {
		if (summary == null) return;
		entity.setRulesEvaluated(summary.rulesEvaluated());
		entity.setExecutionSnapshotJson(CodeScanExecutionSnapshotCodec.encode(summary.codeSnapshot()));
		entity.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(summary.scanners()));
	}

	/**
	 * Get the {@linkplain UploadScanContainerEntity} for the given ticket
	 * 
	 * @param ticket the ticket for the scan
	 * @return a {@linkplain UploadScanContainerEntity} for the ticket, or null if it can't be found
	 */
	public UploadScanContainerEntity findUploadScanByTicket(String ticket) {
		return uploadRepo.findByTicket(ticket);
	}


	/**
	 * Given an {@linkplain UploadScan} configuration and a reason, return an
	 * {@linkplain UploadScanResult} indicating the scan failed for the given reason.
	 * <p>
	 * Note: this is used before a scan begins
	 * 
	 * @param scan   the {@linkplain UploadScan} to give a result for
	 * @param reason the reason the scan failed
	 * @return the {@linkplain UploadScanResult} indicating the scan failure
	 */
	public UploadScanResult generateFailedUploadResult(UploadScan scan, String reason) {
		UploadScanResult res = new UploadScanResult();
		res.setName(scan.getName());
		res.setSubmitDate(Instant.ofEpochMilli(scan.getSubmitDate()).atZone(ZoneId.systemDefault())
				.toLocalDateTime());
		res.setSubmittedBy(scan.getUser());
		res.setStatus(ScanStatus.FAILED.getDisplayName());
		res.setErrorMessage(reason);
		return res;
	}

	/**
	 * Given an scan ticket, return an {@linkplain UploadScanResult} indicating the scan results.
	 * This may include a result that the ticket is unknown, the scan has failed, is in progress, or
	 * is complete with a report.
	 * <p>
	 * Note: this is used after a scan begins
	 * 
	 * @param ticket the scan ticket to give a result for
	 * @return the {@linkplain UploadScanResult} indicating the current scan result
	 */
	public UploadScanResult generateResultForTicket(String ticket) {
		UploadScanResult res;
		UploadScanContainerEntity use = findUploadScanByTicket(ticket);
		if (use == null) {
			res = new UploadScanResult();
			res.setName("UNKNOWN");
			res.setStatus(ScanStatus.FAILED.getDisplayName());
			res.setErrorMessage("Unknown Ticket");
			return res;
		}
		UploadScanEntity scan = use.getLatestUploadScan();
		if (scan != null) {
			res = generateResultForScan(scan);
		} else {
			res = new UploadScanResult();
			res.setName(use.getName());
			res.setSubmittedBy(use.getSubmitter());
			res.setTicket(use.getTicket());
			res.setRuleset(use.getRuleSet());
			res.setStatus(ScanStatus.NOT_STARTED.getDisplayName());
		}
		return res;
	}

	private UploadScanResult generateResultForScan(UploadScanEntity scanEntity) {
		UploadScanResult result = new UploadScanResult();
		UploadScanContainerEntity container = scanEntity.getContainer();
		result.setName(container.getName());
		result.setRuleset(container.getRuleSet());
		result.setSubmittedBy(container.getSubmitter());
		result.setTicket(container.getTicket());
		result.setSubmitDate(scanEntity.getSubmitDate());
		result.setStatus(scanEntity.getStatus().getDisplayName());
		result.setErrorMessage(scanEntity.getError());
		result.setExecutionSummary(new ScanExecutionSummary(scanEntity.getRulesEvaluated(),
				ScanExecutionSummaryCodec.decode(scanEntity.getScannerExecutionsJson())));
		if (scanEntity.getStatus() == ScanStatus.DONE) {
			result.setEndDate(scanEntity.getEndDate());
			long scannedAtMillis = scanEntity.getEndDateMillis();
			result.setViolations(scanEntity.getViolations().stream()
					.map(violation -> generateResultForViolation(violation, scannedAtMillis))
					.sorted(Comparator.comparingInt(UploadScanResultViolation::getSeverityValue))
					.collect(Collectors.toList()));
		}

		return result;
	}

	private UploadScanResultViolation generateResultForViolation(UploadViolationEntity violation,
			long scannedAtMillis) {
		UploadScanResultViolation urv = new UploadScanResultViolation();
  urv.setViolationId(violation.getId());
		urv.setViolationName(violation.getViolationName());
		urv.setLineNumber(violation.getLineNum());
		urv.setSeverity(violation.getSeverity().getName());
		urv.setSeverityValue(violation.getSeverity().getPriority());
		urv.setFileName(violation.getFileName());

		String message = "No guidance written for this rule yet.";
		String extUrl = "";
		RuleEntity rule = ruleService.getRule(violation.getViolationName());
		if (rule != null) {
			message = rule.getMessage();
			extUrl = rule.getExternalUrl();
			if (ruleService.changedAfter(rule, scannedAtMillis)) {
				urv.setRuleChange(RuleChange.CHANGED);
			}
		} else {
			urv.setRuleChange(RuleChange.DELETED);
		}
		urv.setMessage(message);
		urv.setExternalUrl(extUrl);
		return urv;
	}


	/**
	 * Given a {@linkplain ScanStatus} get a list of {@linkplain UploadScanContainerEntity} objects
	 * that match that status
	 * 
	 * @param status the status to search with
	 * @return a list of {@linkplain UploadScanContainerEntity} objects that match the status
	 */
	public List<UploadScanContainerEntity> findUploadsByStatus(ScanStatus status) {
		return scanRepo.findByStatus(status).stream()
				.map(se -> se.getContainer())
				.collect(Collectors.toList());
	}

	public PagedResult<UploadScanResult> getScanResultsWithFilters(UploadResultFilter filter,
			int pageSize, int pageNum) {
		switch (filter) {
			case ALL:
				return PagedResult.of(
						scanRepo.findAll(
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateResultForScan);
			case VIOLATIONS:
				return PagedResult.of(
						vioRepo.findAllGroupByScan(
								PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "scan"))),
						this::generateResultForScan);
			case INCOMPLETE:
				return PagedResult.of(
						scanRepo.findByStatusIn(
								Arrays.asList(ScanStatus.FAILED, ScanStatus.IN_PROGRESS,
										ScanStatus.NOT_STARTED),
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateResultForScan);
			default:
				LOG.error("Filter is not configured to get Uploads");
				throw new IllegalArgumentException("Filter is not configured to get Uploads");
		}
	}
}

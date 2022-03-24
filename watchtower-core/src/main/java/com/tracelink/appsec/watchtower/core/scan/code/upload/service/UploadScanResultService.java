package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
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

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
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
		use.setZipPath(upload.getFilePath());
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
	 * @param violations the list of {@linkplain AbstractViolationEntity} to save against this scan
	 */
	public void saveFinalUploadScan(String ticket,
			List<UploadViolationEntity> violations) {
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
		UploadScanEntity savedScanEntity = scanRepo.saveAndFlush(scan);

		violations.forEach(v -> {
			v.setScan(savedScanEntity);
			vioRepo.save(v);
		});

		vioRepo.flush();
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
		if (scanEntity.getStatus() == ScanStatus.DONE) {
			result.setEndDate(scanEntity.getEndDate());
			result.setViolations(scanEntity.getViolations().stream()
					.map(this::generateResultForViolation)
					.collect(Collectors.toList()));
		}

		return result;
	}

	private UploadScanResultViolation generateResultForViolation(UploadViolationEntity violation) {
		UploadScanResultViolation urv = new UploadScanResultViolation();
		urv.setViolationName(violation.getViolationName());
		urv.setLineNumber(violation.getLineNum());
		urv.setSeverity(violation.getSeverity());
		urv.setSeverityValue(violation.getSeverityValue());
		urv.setFileName(violation.getFileName());

		String message = "Rule guidance not found";
		String extUrl = "";
		RuleEntity rule = ruleService.getRule(violation.getViolationName());
		if (rule != null) {
			message = rule.getMessage();
			extUrl = rule.getExternalUrl();
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

	public List<UploadScanResult> getScanResultsWithFilters(UploadResultFilter filter,
			int pageSize, int pageNum) {
		List<UploadScanResult> results;
		switch (filter) {
			case ALL:
				results =
						scanRepo.findAll(
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate")))
								.stream().map(this::generateResultForScan)
								.collect(Collectors.toList());
				break;
			case VIOLATIONS:
				results = vioRepo
						.findAllGroupByScan(
								PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "scan")))
						.stream()
						.map(this::generateResultForScan)
						.collect(Collectors.toList());
				break;
			case INCOMPLETE:
				results = scanRepo
						.findByStatusIn(
								Arrays.asList(ScanStatus.FAILED, ScanStatus.IN_PROGRESS,
										ScanStatus.NOT_STARTED),
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate")))
						.stream().map(this::generateResultForScan).collect(Collectors.toList());
				break;
			default:
				LOG.error("Filter is not configured to get Uploads");
				throw new IllegalArgumentException("Filter is not configured to get Uploads");
		}
		return results;
	}
}


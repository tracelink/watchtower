package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.registry.RegistryImageRepository;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanError;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultViolation;

/**
 * Handles logic around storing a retrieving scan results
 *
 * @author csmith
 */
@Service
public class ImageScanResultService
		extends AbstractScanResultService<ImageScanEntity, ImageViolationEntity> {
	private static Logger LOG = LoggerFactory.getLogger(ImageScanResultService.class);

	private ImageContainerRepository containerRepo;

	private RegistryImageRepository imageRepo;

	private ImageScanRepository scanRepo;

	private ImageViolationRepository vioRepo;

	private AdvisoryRepository advisoryRepo;

	private RuleService ruleService;

	private APIIntegrationService apiIntegrationService;

	public ImageScanResultService(
			@Autowired ImageContainerRepository prRepo,
			@Autowired RegistryImageRepository imageRepo,
			@Autowired ImageScanRepository scanRepo,
			@Autowired ImageViolationRepository vioRepo,
			@Autowired AdvisoryRepository advisoryRepo,
			@Autowired RuleService ruleService,
			@Autowired APIIntegrationService apiIntegrationService) {
		super(scanRepo, vioRepo);
		this.containerRepo = prRepo;
		this.imageRepo = imageRepo;
		this.scanRepo = scanRepo;
		this.vioRepo = vioRepo;
		this.advisoryRepo = advisoryRepo;
		this.ruleService = ruleService;
		this.apiIntegrationService = apiIntegrationService;
	}

	/**
	 * Counts the number of repositories that have been scanned
	 *
	 * @return number of repositories scanned
	 */
	public long countImages() {
		return imageRepo.count();
	}

	/**
	 * Counts the number of pull requests that have been scanned
	 *
	 * @return number of pull requests scanned
	 */
	public long countContainers() {
		return this.containerRepo.count();
	}

	public AdvisoryEntity getOrCreateAdvisory(ImageScanViolation sv) {
		AdvisoryEntity advisory = advisoryRepo.findByAdvisoryName(sv.getFindingName());
		if (advisory == null) {
			advisory = new AdvisoryEntity();
			advisory.setAdvisoryName(sv.getFindingName());
			advisory.setDescription(sv.getDescription());
			advisory.setPackageName(sv.getPackageName());
			advisory.setScore(sv.getScore());
			advisory.setUri(sv.getUri());
			advisory.setVector(sv.getVector());
			advisoryRepo.save(advisory);
		}
		return advisory;
	}

	public List<AdvisoryEntity> getAllAdvisories() {
		return advisoryRepo.findAll();
	}

	public void saveImageReport(ImageScan scan, long startTime,
			List<ImageViolationEntity> violations,
			List<ImageScanError> errors) {
		if (violations == null) {
			return;
		}
		long now = System.currentTimeMillis();
		ImageScanContainerEntity imageEntity =
				containerRepo.findOneByApiLabelAndImageNameAndTagName(scan.getApiLabel(),
						scan.getImageName(), scan.getTagName());
		if (imageEntity == null) {
			imageEntity = new ImageScanContainerEntity(scan);
			imageEntity = containerRepo.saveAndFlush(imageEntity);
		}
		// TODO should we set a resolved flag?
		imageEntity.setLastReviewedDate(now);
		ImageScanContainerEntity savedImageEntity = containerRepo.saveAndFlush(imageEntity);

		ImageScanEntity scanEntity = new ImageScanEntity();
		scanEntity.setContainer(savedImageEntity);
		scanEntity.setEndDate(now);
		scanEntity.setSubmitDate(scan.getSubmitTime());
		scanEntity.setStartDate(startTime);
		scanEntity.setStatus(ScanStatus.DONE);
		if (!errors.isEmpty()) {
			scanEntity.setError(errors.stream().map(ImageScanError::getErrorMessage)
					.collect(Collectors.joining(", ")));
		}

		ImageScanEntity savedScanEntity = scanRepo.saveAndFlush(scanEntity);

		violations.forEach(v -> {
			v.setScan(savedScanEntity);
			vioRepo.save(v);
		});
		vioRepo.flush();
	}

	public List<ImageScanResult> getScanResultsWithFilters(ImageResultFilter resultFilter,
			int pageSize,
			int pageNum) {
		List<ImageScanResult> results;
		switch (resultFilter) {
			case ALL:
				results = scanRepo.findAll(
						PageRequest.of(pageNum, pageSize,
								Sort.by(Direction.DESC, "endDate")))
						.stream().map(this::generateResultForScan)
						.collect(Collectors.toList());
				break;
			case VIOLATIONS:
				results = vioRepo
						.findAllGroupByScan(
								PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "scan")))
						.stream().map(this::generateResultForScan)
						.collect(Collectors.toList());
				break;
			default:
				LOG.error("Filter is not configured to get Images");
				throw new IllegalArgumentException("Filter is not configured to get Images");
		}
		return results;
	}

	public ImageScanResult generateResultForScan(ImageScanEntity scanEntity) {
		ImageScanResult result = new ImageScanResult();
		ImageScanContainerEntity container = scanEntity.getContainer();
		result.setId(scanEntity.getId());
		result.setApiLabel(container.getApiLabel());
		result.setImageName(container.getImageName());
		result.setTagName(container.getTagName());
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

	private ImageScanResultViolation generateResultForViolation(ImageViolationEntity violation) {
		ImageScanResultViolation irv = new ImageScanResultViolation();
		AdvisoryEntity advisory = violation.getAdvisory();

		irv.setViolationName(violation.getViolationName());
		irv.setSeverity(violation.getSeverity().getName());
		irv.setScore(advisory.getScore());
		irv.setPackageName(advisory.getPackageName());
		irv.setVector(advisory.getVector());
		irv.setDescription(advisory.getDescription());
		irv.setUri(advisory.getUri());

		return irv;
	}

	public ImageScanEntity findById(long id) {
		return scanRepo.findById(id);
	}

}

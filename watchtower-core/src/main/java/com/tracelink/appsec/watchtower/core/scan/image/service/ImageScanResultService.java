package com.tracelink.appsec.watchtower.core.scan.image.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.registry.RegistryImageRepository;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageViolationRepository;

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


}

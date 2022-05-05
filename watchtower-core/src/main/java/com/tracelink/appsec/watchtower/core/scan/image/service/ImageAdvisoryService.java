package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;

/**
 * Service used to CRUD Advisory Entities
 * 
 * @author csmith
 *
 */
@Service
public class ImageAdvisoryService {

	private final AdvisoryRepository advisoryRepo;

	public ImageAdvisoryService(@Autowired AdvisoryRepository advisoryRepo) {
		this.advisoryRepo = advisoryRepo;
	}

	public AdvisoryEntity getOrCreateAdvisory(ImageScanViolation sv) {
		AdvisoryEntity advisory = findByName(sv.getFindingName());
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

	public AdvisoryEntity findByName(String name) {
		return advisoryRepo.findByAdvisoryName(name);
	}

	public List<AdvisoryEntity> getAllAdvisories() {
		return advisoryRepo.findAll();
	}

	public long getTotalNumberAdvisories() {
		return advisoryRepo.count();
	}

}

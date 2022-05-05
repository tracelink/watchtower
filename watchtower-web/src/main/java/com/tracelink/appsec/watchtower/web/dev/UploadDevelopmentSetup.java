package com.tracelink.appsec.watchtower.web.dev;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

/**
 * Setup script to pre-populate Watchtower with a random assortment of scans, violations, rules,
 * etc. Uses a fixed seed for the RNG so that repeated startups have the same set of items.
 *
 * @author csmith, mcool
 */
class UploadDevelopmentSetup {

	private static final int UP_NUM_SIZE = 1000;

	private final UploadScanResultService uploadScanResultService;
	private final UploadContainerRepository uploadRepo;
	private final UploadScanRepository uploadScanRepo;

	UploadDevelopmentSetup(
			@Autowired UploadScanResultService uploadScanResultService,
			@Autowired UploadContainerRepository uploadRepo,
			@Autowired UploadScanRepository uploadScanRepo) {
		this.uploadScanResultService = uploadScanResultService;
		this.uploadRepo = uploadRepo;
		this.uploadScanRepo = uploadScanRepo;
	}


	public void addUploadScanHistory(Random random) {
		for (int i = 0; i < UP_NUM_SIZE; i++) {
			int failedScanChance = random.nextInt(1000);
			saveUpload(failedScanChance == 0, random);
		}
		backdateUploads(random);
	}

	private void saveUpload(boolean state, Random random) {
		UploadScan upload = new UploadScan();
		String name = "foo" + random.nextInt();
		upload.setFilePath(Paths.get(name + ".zip"));
		upload.setName(name);
		upload.setRuleSetName("Fake Ruleset");
		upload.setUser("fake user");
		UploadScanContainerEntity entity = uploadScanResultService.makeNewScanEntity(upload);
		if (state) {
			uploadScanResultService.markScanFailed(entity.getTicket(), "Failed due to failure");
			return;
		}

		// 50% chance of 0 vios, then 25% chance of 1,2,3,4 vios
		int numVios = random.nextBoolean() ? 0 : 1 + random.nextInt(4);
		List<UploadViolationEntity> vios = new ArrayList<>();
		for (int i = 0; i < numVios; i++) {
			vios.add(makeUploadVio(state, random));
		}

		uploadScanResultService.saveFinalUploadScan(entity.getTicket(), vios);
	}

	private UploadViolationEntity makeUploadVio(boolean hasNoBlocking, Random random) {
		UploadViolationEntity vio = new UploadViolationEntity();
		vio.setBlocking(hasNoBlocking ? false : random.nextBoolean());
		vio.setFileName("foobar");
		vio.setLineNum(1);
		vio.setMessage("Test Violation");
		vio.setNewViolation(random.nextDouble() < .3);
		vio.setSeverity(RulePriority.HIGH);
		vio.setViolationName("TestViolation" + random.nextInt(3));
		return vio;
	}

	private void backdateUploads(Random random) {
		long now = System.currentTimeMillis();
		long fiveMin = 5 * 60 * 1000;
		int sixHoursInSeconds = 6 * 60 * 60;
		int tenSeconds = 1 * 60;

		int page = 0;
		Page<UploadScanContainerEntity> pageEntity;
		do {
			pageEntity =
					uploadRepo.findAll(PageRequest.of(page, 1000, Sort.by(Direction.DESC, "id")));
			for (UploadScanContainerEntity upload : pageEntity) {
				long latestNow = now;
				for (UploadScanEntity scanEntity : upload.getScans()) {
					// at least 5 mins apart and at most 6 hours, five minutes apart
					long diff = random.nextInt(sixHoursInSeconds) * 1000L;
					long timeTaken = random.nextInt(tenSeconds) * 1000L;
					now = now - diff - fiveMin;
					scanEntity.setSubmitDate(now - timeTaken);
					scanEntity.setStartDate(now - timeTaken);
					scanEntity.setEndDate(now);
					latestNow = Math.max(latestNow, now);
				}
				upload.setLastReviewedDate(latestNow);
				uploadScanRepo.saveAll(upload.getScans());
			}
			uploadRepo.saveAll(pageEntity);
			page++;
		} while (!pageEntity.isLast());
	}

}

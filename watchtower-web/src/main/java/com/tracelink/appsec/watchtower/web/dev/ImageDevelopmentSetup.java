package com.tracelink.appsec.watchtower.web.dev;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

/**
 * Setup script to pre-populate Watchtower with a random assortment of scans, violations, rules,
 * etc. Uses a fixed seed for the RNG so that repeated startups have the same set of items.
 *
 * @author csmith, mcool
 */
class ImageDevelopmentSetup {

	private static final int IMG_NUM_SIZE = 1000;
	private static final int ADV_NUM_SIZE = 200;

	private final ImageScanResultService imageScanResultService;
	private final ImageAdvisoryService imageAdvisoryService;
	private final ImageContainerRepository imageRepo;
	private final ImageScanRepository imageScanRepo;
	private final RepositoryService repoService;

	ImageDevelopmentSetup(
			RepositoryService repoService,
			ImageAdvisoryService imageAdvisoryService,
			ImageScanResultService imageScanResultService,
			ImageContainerRepository imageRepo,
			ImageScanRepository imageScanRepo) {
		this.repoService = repoService;
		this.imageAdvisoryService = imageAdvisoryService;
		this.imageScanResultService = imageScanResultService;
		this.imageRepo = imageRepo;
		this.imageScanRepo = imageScanRepo;
	}


	public void addImageScanHistory(Random random) {
		List<RepositoryEntity> images =
				repoService.getAllRepos(ImageScanType.CONTAINER).values().stream()
						.flatMap(List::stream).collect(Collectors.toList());
		for (int i = 0; i < ADV_NUM_SIZE; i++) {
			makeAdvisory(random);
		}
		List<AdvisoryEntity> advisories = imageAdvisoryService.getAllAdvisories();
		for (int i = 0; i < IMG_NUM_SIZE; i++) {
			RepositoryEntity image = images.get(random.nextInt(images.size()));
			boolean activeState = random.nextBoolean();
			saveImage(activeState, image, advisories, random);
		}
		backdateImages(random);
	}

	private void makeAdvisory(Random random) {
		ImageScanViolation sv = new ImageScanViolation();
		sv.setFindingName("CVE-" + (2022 - random.nextInt(4)) +
				"-" + (random.nextInt(1000) + 1000));
		sv.setDescription("CVE Description Test");
		sv.setPackageName("CVE Package Name");
		double score = random.nextDouble() * 10.0;
		sv.setScore(String.format("%.2f", score));
		sv.setSeverity(RulePriority.valueOf(5 - (int) (score / (10 / 4))));
		sv.setUri("https://nvd.nist.gov/view/vuln/detail?vulnId=" + sv.getFindingName());
		sv.setVector("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
		this.imageScanResultService.getOrCreateAdvisory(sv);
	}


	private void saveImage(boolean activeState, RepositoryEntity image,
			List<AdvisoryEntity> advisories, Random random) {
		ImageScan imageScan = new EcrImageScan(image.getApiLabel());
		imageScan.setRepository(image.getRepoName());
		imageScan.setTag("v1.0");
		// 50% chance of 0 vios, then 25% chance of 1,2,3,4 vios
		int numVios = random.nextBoolean() ? 0 : 1 + random.nextInt(4);
		List<ImageViolationEntity> vios = new ArrayList<>();
		for (int i = 0; i < numVios; i++) {
			vios.add(makeImageVio(activeState, advisories, random));
		}
		imageScanResultService.saveImageReport(imageScan, 0, vios, new ArrayList<>());
	}

	private ImageViolationEntity makeImageVio(boolean hasNoBlocking,
			List<AdvisoryEntity> advisories, Random random) {
		ImageViolationEntity vio = new ImageViolationEntity();
		vio.setBlocking(hasNoBlocking ? false : random.nextBoolean());
		vio.setSeverity(RulePriority.HIGH);
		vio.setAdvisory(advisories.get(random.nextInt(advisories.size())));
		vio.setViolationName(vio.getAdvisory().getAdvisoryName());
		return vio;
	}

	private void backdateImages(Random random) {
		long now = System.currentTimeMillis();
		long fiveMin = 5 * 60 * 1000;
		int sixHoursInSeconds = 6 * 60 * 60;
		int tenSeconds = 1 * 60;

		int page = 0;
		Page<ImageScanContainerEntity> pageEntity;
		do {
			pageEntity =
					imageRepo.findAll(PageRequest.of(page, 1000, Sort.by(Direction.DESC, "id")));
			for (ImageScanContainerEntity image : pageEntity) {
				long latestNow = now;
				for (ImageScanEntity scanEntity : image.getScans()) {
					// at least 5 mins apart and at most 6 hours, five minutes apart
					long diff = random.nextInt(sixHoursInSeconds) * 1000L;
					long timeTaken = random.nextInt(tenSeconds) * 1000L;
					now = now - diff - fiveMin;
					scanEntity.setSubmitDate(now - timeTaken);
					scanEntity.setStartDate(now - timeTaken);
					scanEntity.setEndDate(now);
					latestNow = Math.max(latestNow, now);
				}
				image.setLastReviewedDate(latestNow);
				imageScanRepo.saveAll(image.getScans());
			}
			imageRepo.saveAll(pageEntity);
			page++;
		} while (!pageEntity.isLast());
	}

}

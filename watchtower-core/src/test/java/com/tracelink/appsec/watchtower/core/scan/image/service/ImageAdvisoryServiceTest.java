package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.image.ImageScanReportTests;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntityTest;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;

@ExtendWith(SpringExtension.class)
public class ImageAdvisoryServiceTest {

	@MockitoBean
	private AdvisoryRepository advisoryRepo;

	private ImageAdvisoryService advisoryService;

	@BeforeEach
	public void setup() {
		advisoryService = new ImageAdvisoryService(advisoryRepo);
	}

	@Test
	public void testGetAdvisory() {
		AdvisoryEntity advisory = AdvisoryEntityTest.buildStandardAdvisory();
		BDDMockito.when(advisoryRepo.findByAdvisoryName(BDDMockito.anyString()))
				.thenReturn(advisory);
		AdvisoryEntity retAdvisory = advisoryService
				.getOrCreateAdvisory(ImageScanReportTests.buildStandardImageScanViolation());
		Assertions.assertEquals(advisory, retAdvisory);
		BDDMockito.verify(advisoryRepo, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testCreateAdvisory() {
		BDDMockito.when(advisoryRepo.findByAdvisoryName(BDDMockito.anyString()))
				.thenReturn(null);
		AdvisoryEntity retAdvisory = advisoryService
				.getOrCreateAdvisory(ImageScanReportTests.buildStandardImageScanViolation());
		Assertions.assertEquals(ImageScanReportTests.description, retAdvisory.getDescription());
		Assertions.assertEquals(ImageScanReportTests.findingName, retAdvisory.getAdvisoryName());
		Assertions.assertEquals(ImageScanReportTests.packageName, retAdvisory.getPackageName());
		Assertions.assertEquals(ImageScanReportTests.score, retAdvisory.getScore());
		Assertions.assertEquals(ImageScanReportTests.uri, retAdvisory.getUri());
		Assertions.assertEquals(ImageScanReportTests.vector, retAdvisory.getVector());
		BDDMockito.verify(advisoryRepo).save(BDDMockito.any());
	}

	@Test
	public void testFindByName() {
		AdvisoryEntity advisory = new AdvisoryEntity();
		BDDMockito.when(advisoryRepo.findByAdvisoryName(BDDMockito.anyString()))
				.thenReturn(advisory);
		Assertions.assertEquals(advisory, advisoryService.findByName("foo"));
	}

	@Test
	public void testGetAllAdvisories() {
		List<AdvisoryEntity> advisory = Arrays.asList(new AdvisoryEntity());
		BDDMockito.when(advisoryRepo.findAll())
				.thenReturn(advisory);
		Assertions.assertEquals(advisory, advisoryService.getAllAdvisories());
	}

	@Test
	public void testGetTotalAdvisories() {
		long count = 6L;
		BDDMockito.when(advisoryRepo.count()).thenReturn(count);
		Assertions.assertEquals(count, advisoryService.getTotalNumberAdvisories());
	}

	private static AdvisoryRepository.AdvisorySummary summary(long id, String name, String score) {
		return new AdvisoryRepository.AdvisorySummary() {
			public long getId() { return id; }
			public String getAdvisoryName() { return name; }
			public String getScore() { return score; }
		};
	}

	private static AdvisoryEntity advisory(long id, String name) {
		AdvisoryEntity entity = new AdvisoryEntity();
		entity.setAdvisoryName(name);
		return entity;
	}

	@Test
	public void searchFiltersByScoreSortsHighestFirstAndPages() {
		BDDMockito.when(advisoryRepo.searchSummaries("%cve!_%")).thenReturn(List.of(summary(1, "CVE-A", "5.0"),
				summary(2, "CVE-B", "9.8"), summary(3, "CVE-C", "not scored"), summary(4, "CVE-D", "7.5")));
		BDDMockito.when(advisoryRepo.findAllById(List.of(4L))).thenReturn(List.of(advisory(4, "CVE-D")));

		var page = advisoryService.search("CVE_", 7.0, "score", 1, 1);

		Assertions.assertEquals(2, page.total(), "only scored advisories at or above 7.0");
		Assertions.assertEquals(List.of("CVE-D"), page.advisories().stream().map(AdvisoryEntity::getAdvisoryName).toList());
	}

	@Test
	public void searchByNameKeepsUnscoredAdvisoriesAndRejectsBadInput() {
		BDDMockito.when(advisoryRepo.searchSummaries("%%")).thenReturn(List.of(summary(2, "CVE-B", "9.8"),
				summary(3, "CVE-A", null)));
		BDDMockito.when(advisoryRepo.findAllById(List.of(3L, 2L))).thenReturn(List.of(advisory(2, "CVE-B"), advisory(3, "CVE-A")));

		var page = advisoryService.search("", 0, "name", 0, 25);

		Assertions.assertEquals(List.of("CVE-A", "CVE-B"), page.advisories().stream().map(AdvisoryEntity::getAdvisoryName).toList());
		Assertions.assertThrows(IllegalArgumentException.class, () -> advisoryService.search("", 0, "bogus", 0, 25));
		Assertions.assertThrows(IllegalArgumentException.class, () -> advisoryService.search("", 11, "name", 0, 25));
		Assertions.assertThrows(IllegalArgumentException.class, () -> advisoryService.search("", 0, "name", 0, 101));
	}
}

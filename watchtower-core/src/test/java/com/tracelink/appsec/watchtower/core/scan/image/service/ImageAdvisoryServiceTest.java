package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.image.ImageScanReportTests;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntityTest;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;

@ExtendWith(SpringExtension.class)
public class ImageAdvisoryServiceTest {

	@MockBean
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
}

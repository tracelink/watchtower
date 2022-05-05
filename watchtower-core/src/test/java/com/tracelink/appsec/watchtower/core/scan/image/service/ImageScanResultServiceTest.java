package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanReportTests;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScanTest;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntityTests;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanError;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

@ExtendWith(SpringExtension.class)
public class ImageScanResultServiceTest {

	@MockBean
	private ImageContainerRepository containerRepo;

	@MockBean
	private RepositoryRepository imageRepo;

	@MockBean
	private ImageScanRepository scanRepo;

	@MockBean
	private ImageViolationRepository vioRepo;

	private ImageScanResultService imageScanResultService;

	@BeforeEach
	public void setup() {
		imageScanResultService =
				new ImageScanResultService(containerRepo, imageRepo, scanRepo, vioRepo);
	}

	@Test
	public void testCountContainers() {
		long count = 123L;
		BDDMockito.when(containerRepo.count()).thenReturn(count);
		Assertions.assertEquals(count, imageScanResultService.countContainers());
	}

	@Test
	public void testCountImages() {
		long count = 123L;
		BDDMockito.when(imageRepo.count()).thenReturn(count);
		Assertions.assertEquals(count, imageScanResultService.countImages());
	}

	@Test
	public void testFindById() {
		ImageScanEntity entity = new ImageScanEntity();
		BDDMockito.when(scanRepo.findById(BDDMockito.anyLong())).thenReturn(entity);
		Assertions.assertEquals(entity, imageScanResultService.findById(1L));
	}

	@Test
	public void testSaveImageReport() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		ImageViolationEntity violation = ImageScanEntityTests.buildStandardViolation();
		BDDMockito.when(containerRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		BDDMockito.when(scanRepo.saveAndFlush(BDDMockito.any()))
				.thenAnswer(e -> e.getArgument(0));
		ImageScanError error = ImageScanReportTests.buildStandardError();
		imageScanResultService.saveImageReport(scan, 0L, Arrays.asList(violation),
				Arrays.asList(error));
		BDDMockito.verify(vioRepo).save(BDDMockito.any());
	}

	@Test
	public void testSaveImageReportNullViolations() {
		imageScanResultService.saveImageReport(null, 0L, null, null);
		BDDMockito.verify(vioRepo, BDDMockito.never()).save(BDDMockito.any());
		BDDMockito.verify(containerRepo, BDDMockito.never()).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testGetScanResultsWithFiltersALL() {
		ImageScanEntity scanEntity = ImageScanEntityTests.buildStandardScan();
		scanEntity.setViolations(Arrays.asList(ImageScanEntityTests.buildStandardViolation()));
		BDDMockito.when(scanRepo.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<ImageScanEntity>(Arrays.asList(scanEntity)));
		List<ImageScanResult> results =
				imageScanResultService.getScanResultsWithFilters(ImageResultFilter.ALL, 1, 1);
		Assertions.assertEquals(1, results.size());
		Assertions.assertEquals(scanEntity.getContainer().getRepositoryName(),
				results.get(0).getRepositoryName());
	}

	@Test
	public void testGetScanResultsWithFiltersVIOLATIONS() {
		ImageScanEntity scanEntity = ImageScanEntityTests.buildStandardScan();
		scanEntity.setViolations(Arrays.asList(ImageScanEntityTests.buildStandardViolation()));
		BDDMockito.when(vioRepo.findAllGroupByScan(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<ImageScanEntity>(Arrays.asList(scanEntity)));
		List<ImageScanResult> results = imageScanResultService
				.getScanResultsWithFilters(ImageResultFilter.VIOLATIONS, 1, 1);
		Assertions.assertEquals(1, results.size());
		Assertions.assertEquals(scanEntity.getContainer().getRepositoryName(),
				results.get(0).getRepositoryName());
	}

}

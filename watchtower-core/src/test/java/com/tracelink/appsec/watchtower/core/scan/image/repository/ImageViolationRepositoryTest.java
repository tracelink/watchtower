package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;

/**
 * Hibernate 7 HQL parse-compatibility check for {@link ImageViolationRepository}'s hand-written
 * {@code @Query} method. See {@code PRScanRepositoryTest} for why this class of test exists.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class ImageViolationRepositoryTest {

	@Autowired
	private ImageViolationRepository imageViolationRepository;

	@Test
	public void testFindAllGroupByScanParses() {
		Page<ImageScanEntity> result =
				imageViolationRepository.findAllGroupByScan(PageRequest.of(0, 10));
		Assertions.assertTrue(result.isEmpty());
	}

}

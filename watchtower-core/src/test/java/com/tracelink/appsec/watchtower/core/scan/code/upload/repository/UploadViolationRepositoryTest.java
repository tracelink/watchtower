package com.tracelink.appsec.watchtower.core.scan.code.upload.repository;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;

/**
 * Hibernate 7 HQL parse-compatibility check for {@link UploadViolationRepository}'s hand-written
 * {@code @Query} method. See {@code PRScanRepositoryTest} for why this class of test exists.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class UploadViolationRepositoryTest {

	@Autowired
	private UploadViolationRepository uploadViolationRepository;

	@Test
	public void testFindAllGroupByScanParses() {
		Page<UploadScanEntity> result =
				uploadViolationRepository.findAllGroupByScan(PageRequest.of(0, 10));
		Assertions.assertTrue(result.isEmpty());
	}

}

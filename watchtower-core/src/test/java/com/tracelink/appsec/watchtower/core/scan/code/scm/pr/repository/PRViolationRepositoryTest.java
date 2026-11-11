package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/**
 * Hibernate 7 HQL parse-compatibility check for {@link PRViolationRepository}'s hand-written
 * {@code @Query} method. See {@link PRScanRepositoryTest} for why this class of test exists.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class PRViolationRepositoryTest {

	@Autowired
	private PRViolationRepository prViolationRepository;

	@Test
	public void testFindAllNonMCRGroupByScanParses() {
		Slice<PullRequestScanEntity> result =
				prViolationRepository.findAllNonMCRGroupByScan(PageRequest.of(0, 10));
		Assertions.assertTrue(result.isEmpty());
	}

}

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
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/**
 * Hibernate 7 HQL parse-compatibility check for {@link PRScanRepository}'s hand-written
 * {@code @Query} methods. These use a correlated subquery whose HAVING clause references the
 * outer query's alias - a shape that parsed loosely under the old Hibernate 5.6 translator and
 * is a plausible target for the ANTLR-based HQL parser introduced in Hibernate 6+. No test in
 * this codebase previously exercised a real (non-mocked) repository, so these queries had never
 * been parsed by any Hibernate version until this test was added. An empty table is sufficient:
 * a parse failure throws regardless of row count.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class PRScanRepositoryTest {

	@Autowired
	private PRScanRepository prScanRepository;

	@Autowired
	private PRContainerRepository prContainerRepository;

	@Test
	public void testFindLatestMcrsPerPRByMcrStatusParses() {
		Slice<PullRequestScanEntity> result = prScanRepository
				.findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus.PENDING_REVIEW,
						PageRequest.of(0, 10));
		Assertions.assertTrue(result.isEmpty());
	}

	@Test
	public void testMcrStatusRoundTripsThroughDatabase() {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		container.setApiLabel("label");
		container.setRepoName("repo");
		container.setPrId("prId");
		container.setAuthor("author");
		container.setSourceBranch("srcBranch");
		container.setDestinationBranch("dstBranch");
		container = prContainerRepository.save(container);

		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(container);
		scan.setSubmitDate(System.currentTimeMillis());
		scan.setEndDate(System.currentTimeMillis());
		scan.setStatus(ScanStatus.DONE);
		scan.setMcrStatus(PullRequestMCRStatus.RECOMMENDATIONS);
		scan = prScanRepository.save(scan);
		prScanRepository.flush();

		PullRequestScanEntity found = prScanRepository.findById(scan.getId());
		Assertions.assertEquals(PullRequestMCRStatus.RECOMMENDATIONS, found.getMcrStatus());
	}

	@Test
	public void testFindLatestMcrsPerPRParses() {
		Slice<PullRequestScanEntity> result = prScanRepository
				.findLatestMcrsPerPR(PullRequestMCRStatus.PENDING_REVIEW, PageRequest.of(0, 10));
		Assertions.assertTrue(result.isEmpty());
	}

}

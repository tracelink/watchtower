package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

/**
 * Runs the repository-settings queries against the real Flyway schema.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class RepositoryRepositoryTest {

	@Autowired
	private RepositoryRepository repoRepo;

	@BeforeEach
	public void seed() {
		repoRepo.deleteAll();
		save("zeta-bb", "payments-api", CodeScanType.PULL_REQUEST);
		save("alpha-bb", "Billing-Service", CodeScanType.PULL_REQUEST);
		save("alpha-bb", "billing-ui", CodeScanType.PULL_REQUEST);
		save("alpha-bb", "inventory", CodeScanType.PULL_REQUEST);
		save("upload-only", "uploaded-repo", CodeScanType.UPLOAD);
	}

	@Test
	public void testApiLabelsAreDistinctSortedAndScopedToScanType() {
		Assertions.assertEquals(List.of("alpha-bb", "zeta-bb"),
				repoRepo.findApiLabelsByScanType(CodeScanType.PULL_REQUEST));
		Assertions.assertEquals(List.of("upload-only"),
				repoRepo.findApiLabelsByScanType(CodeScanType.UPLOAD));
	}

	@Test
	public void testReposForOneLabelAreFilteredCaseInsensitively() {
		Page<RepositoryEntity> page = repoRepo
				.findByScanTypeAndApiLabelAndRepoNameContainingIgnoreCase(
						CodeScanType.PULL_REQUEST, "alpha-bb", "BILLING", byName(0, 10));

		Assertions.assertEquals(List.of("Billing-Service", "billing-ui"),
				page.getContent().stream().map(RepositoryEntity::getRepoName).toList());
	}

	@Test
	public void testEmptyQueryReturnsAllReposForTheLabelPaged() {
		Page<RepositoryEntity> first = repoRepo
				.findByScanTypeAndApiLabelAndRepoNameContainingIgnoreCase(
						CodeScanType.PULL_REQUEST, "alpha-bb", "", byName(0, 2));

		Assertions.assertEquals(3, first.getTotalElements());
		Assertions.assertEquals(2, first.getTotalPages());
		Assertions.assertEquals(2, first.getContent().size());
	}

	private static PageRequest byName(int page, int size) {
		return PageRequest.of(page, size, Sort.by("repoName").ascending());
	}

	private void save(String apiLabel, String repoName, CodeScanType type) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel(apiLabel);
		repo.setRepoName(repoName);
		repo.setScanType(type);
		repo.setEnabled(true);
		repoRepo.save(repo);
	}
}

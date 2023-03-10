package com.tracelink.appsec.watchtower.web.dev;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

/**
 * Setup script to pre-populate Watchtower with a random assortment of scans, violations, rules,
 * etc. Uses a fixed seed for the RNG so that repeated startups have the same set of items.
 *
 * @author csmith, mcool
 */
public class PRDevelopmentSetup {

	private static final int PR_NUM_SIZE = 1000;
	private static final boolean USE_MULTI_SCANS = true;

	private final RepositoryService repositoryService;
	private final PRScanResultService prScanResultService;
	private final PRContainerRepository prRepo;
	private final PRScanRepository prScanRepo;

	PRDevelopmentSetup(
			RepositoryService repositoryService,
			PRScanResultService prScanResultService,
			PRContainerRepository prRepo,
			PRScanRepository prScanRepo) {
		this.repositoryService = repositoryService;
		this.prScanResultService = prScanResultService;
		this.prRepo = prRepo;
		this.prScanRepo = prScanRepo;
	}

	/**
	 * Setup the PR Development configuation
	 * 
	 * @param random the RNG to use
	 */
	public void addPRScanHistory(Random random) {
		List<RepositoryEntity> repos =
				repositoryService.getAllRepos(CodeScanType.PULL_REQUEST).values().stream()
						.flatMap(List::stream).collect(Collectors.toList());
		for (int i = 0; i < PR_NUM_SIZE; i++) {
			RepositoryEntity repo = repos.get(random.nextInt(repos.size()));
			boolean activeState = random.nextBoolean();
			savePr(activeState, repo, random);
		}
		backdatePrs(random);
	}

	private void backdatePrs(Random random) {
		long now = System.currentTimeMillis();
		long fiveMin = 5 * 60 * 1000;
		int sixHoursInSeconds = 6 * 60 * 60;
		int oneMinInSeconds = 1 * 60;

		int page = 0;
		Page<PullRequestContainerEntity> pageEntity;
		do {
			pageEntity =
					prRepo.findAll(PageRequest.of(page, 1000, Sort.by(Direction.DESC, "id")));
			for (PullRequestContainerEntity pr : pageEntity) {
				long latestNow = now;
				for (PullRequestScanEntity scanEntity : pr.getScans()) {
					// at least 5 mins apart and at most 6 hours, five minutes apart
					long diff = random.nextInt(sixHoursInSeconds) * 1000L;
					long timeTaken = random.nextInt(oneMinInSeconds) * 1000L;
					now = now - diff - fiveMin;
					scanEntity.setSubmitDate(now - timeTaken);
					scanEntity.setStartDate(now - timeTaken);
					scanEntity.setEndDate(now);
					latestNow = Math.max(latestNow, now);
				}
				pr.setLastReviewedDate(latestNow);
				prScanRepo.saveAll(pr.getScans());
			}
			prRepo.saveAll(pageEntity);
			page++;
		} while (!pageEntity.isLast());
	}

	private void savePr(boolean activeState, RepositoryEntity repo, Random random) {
		PullRequest pr = new PullRequest(repo.getApiLabel());
		pr.setAuthor("testAuthor");
		pr.setDestinationBranch("masterTest");
		pr.setPrId(String.valueOf(Math.abs(random.nextInt())));
		pr.setRepoName(repo.getRepoName());
		pr.setSourceBranch("test");
		pr.setState(activeState ? PullRequestState.ACTIVE : PullRequestState.DECLINED);
		// between 1 and 4 scans for this PR
		int numScans = USE_MULTI_SCANS ? random.nextInt(4) + 1 : 1;
		for (int i = 0; i < numScans; i++) {
			// 50% chance of 0 vios, then 25% chance of 1,2,3,4 vios
			int numVios = random.nextBoolean() ? 0 : 1 + random.nextInt(4);
			List<PullRequestViolationEntity> vios = new ArrayList<>();
			for (int j = 0; j < numVios; j++) {
				vios.add(makePRVio(activeState, random));
			}
			prScanResultService.savePullRequestScan(pr, 0, vios, new ArrayList<>());
		}
	}

	private PullRequestViolationEntity makePRVio(boolean hasNoBlocking, Random random) {
		PullRequestViolationEntity vio = new PullRequestViolationEntity();
		vio.setBlocking(hasNoBlocking ? false : random.nextBoolean());
		vio.setBlocking(false);
		vio.setFileName("foobar");
		vio.setLineNum(1);
		vio.setMessage("Test Violation");
		vio.setNewViolation(random.nextDouble() < .3);
		vio.setViolationName(random.nextBoolean() ? "MCR Match: TestViolation" + random.nextInt(3) : "TestViolation" + random.nextInt(3));
		vio.setSeverity(vio.getViolationName().startsWith("MCR Match:") ? RulePriority.INFORMATIONAL : RulePriority.HIGH);
		return vio;
	}
}

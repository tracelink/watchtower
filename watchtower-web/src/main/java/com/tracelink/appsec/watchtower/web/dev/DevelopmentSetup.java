package com.tracelink.appsec.watchtower.web.dev;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.RepositoryService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

/**
 * Setup script to pre-populate Watchtower with a random assortment of scans, violations, rules,
 * etc. Uses a fixed seed for the RNG so that repeated startups have the same set of items.
 *
 * @author csmith, mcool
 */
@Component
public class DevelopmentSetup {

	private static final String ALLOWED_PROFILE = "dev";
	private static final Logger LOG = LoggerFactory.getLogger(DevelopmentSetup.class);
	private static final int PR_NUM_SIZE = 1000;
	private static final int UP_NUM_SIZE = 1000;
	private static final boolean USE_MULTI_SCANS = true;
	private static final long RANDOM_SEED = 1L;
	private static final String API_LABEL_1 = "API1";
	private static final String API_LABEL_2 = "api2";

	private final Environment environment;
	private final APIIntegrationService apiService;
	private final RulesetService rulesetService;
	private final RulesetRepository rulesetRepository;
	private final RepositoryService repositoryService;
	private final PRScanResultService prScanResultService;
	private final PRContainerRepository prRepo;
	private final UploadScanResultService uploadScanResultService;
	private final UploadContainerRepository uploadRepo;
	private final PRScanRepository prScanRepo;
	private final UploadScanRepository uploadScanRepo;
	private final MetricsCacheService metricsService;

	public DevelopmentSetup(@Autowired Environment environment,
			@Autowired APIIntegrationService apiService,
			@Autowired RulesetService rulesetService,
			@Autowired RulesetRepository rulesetRepository,
			@Autowired RepositoryService repositoryService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired PRContainerRepository prRepo,
			@Autowired UploadScanResultService uploadScanResultService,
			@Autowired UploadContainerRepository uploadRepo,
			@Autowired PRScanRepository prScanRepo,
			@Autowired UploadScanRepository uploadScanRepo,
			@Autowired MetricsCacheService metricsService) {
		this.environment = environment;
		this.apiService = apiService;
		this.rulesetService = rulesetService;
		this.rulesetRepository = rulesetRepository;
		this.repositoryService = repositoryService;
		this.prScanResultService = prScanResultService;
		this.prRepo = prRepo;
		this.uploadScanResultService = uploadScanResultService;
		this.uploadRepo = uploadRepo;
		this.prScanRepo = prScanRepo;
		this.uploadScanRepo = uploadScanRepo;
		this.metricsService = metricsService;
	}

	/**
	 * After the app is built, insert all data needed. This pauses the metrics service and
	 * re-enables it after setup so that the data is correct in metrics.
	 *
	 * @param event the app is initialized or restarted
	 * @throws Exception if anything goes wrong
	 */
	@EventListener
	public void onApplicationEvent(ContextRefreshedEvent event) throws Exception {
		if (!environment.acceptsProfiles(Profiles.of(ALLOWED_PROFILE))) {
			return;
		}
		new Thread(() -> {
			metricsService.pause();
			LOG.info("Beginning Dev Setup");
			Random random = new Random(RANDOM_SEED);
			try {
				addApiSettings();
				LOG.info("API configured");
				importRules();
				LOG.info("Rules Imported");
				addRepos();
				LOG.info("Repositories Added");
				addPRScanHistory(random);
				LOG.info("PR Scan History Added");
				addUploadScanHistory(random);
				LOG.info("Upload Scan History Added");
				setSomeReposDisabled(random);
			} catch (Exception e) {
				LOG.info("Dev Setup Failed", e);
			}
			LOG.info("Dev Setup Complete");
			metricsService.resume();
		}).start();
	}

	private void addApiSettings() throws ApiIntegrationException {
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setApiLabel(API_LABEL_1);
		entity.setWorkspace("workspace1");
		entity.setUser("myUser");
		entity.setAuth("myAuth");
		apiService.save(entity);
		BBCloudIntegrationEntity entity2 = new BBCloudIntegrationEntity();
		entity2.setApiLabel(API_LABEL_2);
		entity2.setWorkspace("workspace2");
		entity2.setUser("myUser");
		entity2.setAuth("myAuth");
		apiService.save(entity2);
	}

	private void addRepos() {
		repositoryService.upsertRepo(API_LABEL_1, "Main Product");
		repositoryService.upsertRepo(API_LABEL_1, "Another Product");
		repositoryService.upsertRepo(API_LABEL_2, "Supporting Library");
	}

	private void importRules() throws Exception {
		RulesetEntity defaultRuleset = rulesetService.createRuleset("Default Dev Ruleset",
				"Default Dev Rulesets", RulesetDesignation.PRIMARY);

		defaultRuleset.setRulesets(rulesetRepository.findAll().stream()
				.filter(r -> r.getDesignation() != RulesetDesignation.PRIMARY)
				.collect(Collectors.toSet()));

		RulesetEntity saved = rulesetRepository.saveAndFlush(defaultRuleset);
		rulesetService.setDefaultRuleset(saved.getId());
	}

	private void addPRScanHistory(Random random) {
		List<RepositoryEntity> repos =
				repositoryService.getAllRepos().values().stream().flatMap(List::stream)
						.collect(Collectors.toList());
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
		vio.setFileName("foobar");
		vio.setLineNum(1);
		vio.setMessage("Test Violation");
		vio.setNewViolation(random.nextDouble() < .3);
		vio.setSeverity("High");
		vio.setSeverityValue(1);
		vio.setViolationName("TestViolation" + random.nextInt(3));
		return vio;
	}

	private void addUploadScanHistory(Random random) {
		for (int i = 0; i < UP_NUM_SIZE; i++) {
			int failedScanChance = random.nextInt(1000);
			saveUpload(failedScanChance == 0, random);
		}
		backdateUploads(random);
	}

	private void saveUpload(boolean state, Random random) {
		UploadScan upload = new UploadScan();
		String name = "foo" + random.nextInt();
		upload.setFilePath(Paths.get(name + ".zip"));
		upload.setName(name);
		upload.setRuleSetName("Fake Ruleset");
		upload.setUser("fake user");
		UploadScanContainerEntity entity = uploadScanResultService.makeNewScanEntity(upload);
		if (state) {
			uploadScanResultService.markScanFailed(entity.getTicket(), "Failed due to failure");
			return;
		}

		// 50% chance of 0 vios, then 25% chance of 1,2,3,4 vios
		int numVios = random.nextBoolean() ? 0 : 1 + random.nextInt(4);
		List<UploadViolationEntity> vios = new ArrayList<>();
		for (int i = 0; i < numVios; i++) {
			vios.add(makeUploadVio(state, random));
		}

		uploadScanResultService.saveFinalUploadScan(entity.getTicket(), vios);
	}

	private UploadViolationEntity makeUploadVio(boolean hasNoBlocking, Random random) {
		UploadViolationEntity vio = new UploadViolationEntity();
		vio.setBlocking(hasNoBlocking ? false : random.nextBoolean());
		vio.setFileName("foobar");
		vio.setLineNum(1);
		vio.setMessage("Test Violation");
		vio.setNewViolation(random.nextDouble() < .3);
		vio.setSeverity("High");
		vio.setSeverityValue(1);
		vio.setViolationName("TestViolation" + random.nextInt(3));
		return vio;
	}

	private void backdateUploads(Random random) {
		long now = System.currentTimeMillis();
		long fiveMin = 5 * 60 * 1000;
		int sixHoursInSeconds = 6 * 60 * 60;
		int tenSeconds = 1 * 60;

		int page = 0;
		Page<UploadScanContainerEntity> pageEntity;
		do {
			pageEntity =
					uploadRepo.findAll(PageRequest.of(page, 1000, Sort.by(Direction.DESC, "id")));
			for (UploadScanContainerEntity upload : pageEntity) {
				long latestNow = now;
				for (UploadScanEntity scanEntity : upload.getScans()) {
					// at least 5 mins apart and at most 6 hours, five minutes apart
					long diff = random.nextInt(sixHoursInSeconds) * 1000L;
					long timeTaken = random.nextInt(tenSeconds) * 1000L;
					now = now - diff - fiveMin;
					scanEntity.setSubmitDate(now - timeTaken);
					scanEntity.setStartDate(now - timeTaken);
					scanEntity.setEndDate(now);
					latestNow = Math.max(latestNow, now);
				}
				upload.setLastReviewedDate(latestNow);
				uploadScanRepo.saveAll(upload.getScans());
			}
			uploadRepo.saveAll(pageEntity);
			page++;
		} while (!pageEntity.isLast());
	}

	private void setSomeReposDisabled(Random random) {
		repositoryService.disableRepo(repositoryService.upsertRepo(API_LABEL_1, "Disabled repo1"));
		repositoryService.disableRepo(repositoryService.upsertRepo(API_LABEL_2, "Disabled repo2"));
	}
}

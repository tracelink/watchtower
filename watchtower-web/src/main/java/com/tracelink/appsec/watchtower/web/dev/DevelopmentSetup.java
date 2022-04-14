package com.tracelink.appsec.watchtower.web.dev;

import java.util.Random;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.repository.UploadScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

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
	private static final long RANDOM_SEED = 1L;
	private static final String API_LABEL_1 = "API1";
	private static final String API_LABEL_2 = "api2";

	private static final String IMAGE_API_LABEL_1 = "AccountApi";
	private static final String IMAGE_API_LABEL_2 = "DockerApi";

	private final Environment environment;
	private final APIIntegrationService apiService;
	private final RulesetService rulesetService;
	private final RulesetRepository rulesetRepository;
	private final RepositoryService repositoryService;
	private final MetricsCacheService metricsService;

	private final PRDevelopmentSetup prDevelopmentSetup;
	private final UploadDevelopmentSetup uploadDevelopmentSetup;
	private final ImageDevelopmentSetup imageDevelopmentSetup;

	public DevelopmentSetup(@Autowired Environment environment,
			@Autowired APIIntegrationService apiService,
			@Autowired RulesetService rulesetService,
			@Autowired RulesetRepository rulesetRepository,
			@Autowired RepositoryService repositoryService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired PRContainerRepository prRepo,
			@Autowired PRScanRepository prScanRepo,
			@Autowired UploadScanResultService uploadScanResultService,
			@Autowired UploadContainerRepository uploadRepo,
			@Autowired UploadScanRepository uploadScanRepo,
			@Autowired ImageScanResultService imageScanResultService,
			@Autowired ImageContainerRepository imageRepo,
			@Autowired ImageScanRepository imageScanRepo,
			@Autowired MetricsCacheService metricsService) {
		this.environment = environment;
		this.apiService = apiService;
		this.rulesetService = rulesetService;
		this.rulesetRepository = rulesetRepository;
		this.repositoryService = repositoryService;
		this.metricsService = metricsService;
		prDevelopmentSetup =
				new PRDevelopmentSetup(repositoryService, prScanResultService, prRepo, prScanRepo);
		uploadDevelopmentSetup =
				new UploadDevelopmentSetup(uploadScanResultService, uploadRepo, uploadScanRepo);
		imageDevelopmentSetup = new ImageDevelopmentSetup(repositoryService, imageScanResultService,
				imageRepo, imageScanRepo);
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
				addImages();
				LOG.info("Images Added");
				prDevelopmentSetup.addPRScanHistory(random);
				LOG.info("PR Scan History Added");
				uploadDevelopmentSetup.addUploadScanHistory(random);
				LOG.info("Upload Scan History Added");
				imageDevelopmentSetup.addImageScanHistory(random);
				LOG.info("Image Scan History Added");
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

		EcrIntegrationEntity entity3 = new EcrIntegrationEntity();
		entity3.setApiLabel(IMAGE_API_LABEL_1);
		entity3.setApiKey("apiKey1");
		entity3.setSecretKey("secretKey1");
		apiService.save(entity3);
		EcrIntegrationEntity entity4 = new EcrIntegrationEntity();
		entity4.setApiLabel(IMAGE_API_LABEL_2);
		entity4.setApiKey("apiKey2");
		entity4.setSecretKey("secretKey2");
		apiService.save(entity4);
	}

	private void addRepos() {
		repositoryService.upsertRepo(CodeScanType.PULL_REQUEST, API_LABEL_1, "Main Product");
		repositoryService.upsertRepo(CodeScanType.PULL_REQUEST, API_LABEL_1, "Another Product");
		repositoryService.upsertRepo(CodeScanType.PULL_REQUEST, API_LABEL_2, "Supporting Library");
	}

	private void addImages() {
		repositoryService.upsertRepo(ImageScanType.CONTAINER, IMAGE_API_LABEL_1, "First Image");
		repositoryService.upsertRepo(ImageScanType.CONTAINER, IMAGE_API_LABEL_1, "Custom Image");
		repositoryService.upsertRepo(ImageScanType.CONTAINER, IMAGE_API_LABEL_2, "External Image");
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

	private void setSomeReposDisabled(Random random) {
		repositoryService.disableRepo(repositoryService.upsertRepo(CodeScanType.PULL_REQUEST,
				API_LABEL_1, "Disabled repo1"));
		repositoryService.disableRepo(repositoryService.upsertRepo(CodeScanType.PULL_REQUEST,
				API_LABEL_2, "Disabled repo2"));

		repositoryService.disableRepo(repositoryService.upsertRepo(ImageScanType.CONTAINER,
				IMAGE_API_LABEL_1, "Disabled repo1"));
		repositoryService.disableRepo(repositoryService.upsertRepo(ImageScanType.CONTAINER,
				IMAGE_API_LABEL_2, "Disabled repo2"));
	}
}

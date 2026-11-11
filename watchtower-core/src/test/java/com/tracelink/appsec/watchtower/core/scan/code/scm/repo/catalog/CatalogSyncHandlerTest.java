package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog;

import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.RetryLaterException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.IntegrationHealthService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * Runs a catalog sync against the real Flyway schema with a stubbed SCM listing.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class CatalogSyncHandlerTest {

	@Autowired
	private RepoCatalogDao catalog;

	@Autowired
	private RepositoryRepository repositories;

	@Autowired
	private RepoScanRepository scans;

	@Autowired
	private RepoScanPlanRepository plans;

	private IScmApi api;

	private CatalogSyncHandler handler;

	private final AsyncJobEntity job = new AsyncJobEntity();

	private IntegrationHealthService health;

	@BeforeEach
	public void setup() {
		scans.deleteAll();
		plans.deleteAll();
		repositories.deleteAll();
		api = BDDMockito.mock(IScmApi.class);
		ApiIntegrationEntity integration = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integration.createApi()).thenReturn(api);
		ApiIntegrationService integrations = BDDMockito.mock(ApiIntegrationService.class);
		BDDMockito.when(integrations.findByLabel("bb")).thenReturn(integration);
		health = BDDMockito.mock(IntegrationHealthService.class);
		handler = new CatalogSyncHandler(integrations, BDDMockito.mock(RulesetService.class),
				catalog, health);
		job.setPayload(CatalogSyncHandler.payload("bb"));
	}

	@SuppressWarnings("unchecked")
	private void listing(boolean complete, List<ScmRepository> repos) {
		BDDMockito.willAnswer(i -> {
			((Consumer<List<ScmRepository>>) i.getArgument(0)).accept(repos);
			return complete;
		}).given(api).listRepositories(ArgumentMatchers.any());
	}

	private static ScmRepository listed(String slug, long updatedOn) {
		return new ScmRepository(slug, "PAY", "main", updatedOn, 100, "java");
	}

	private RepositoryEntity find(String name) {
		return repositories.findByApiLabelAndRepoName("bb", name);
	}

	@Test
	public void addsNewRepositoriesAsNotYetPrActive() throws Exception {
		listing(true, List.of(listed("a", 10), listed("b", 20)));

		handler.handle(job, note -> {
		});

		RepositoryEntity a = find("a");
		Assertions.assertTrue(a.isEnabled());
		Assertions.assertFalse(a.isPrActive());
		Assertions.assertEquals("PAY", a.getProjectKey());
		Assertions.assertEquals(10, a.getLastCommitAt());
		Assertions.assertEquals(CodeScanType.PULL_REQUEST, a.getScanType());
	}

	@Test
	public void updatesChangedRowsAndDisablesUnlistedOnlyAfterACompleteListing()
			throws Exception {
		listing(true, List.of(listed("a", 10), listed("old", 5)));
		handler.handle(job, note -> {
		});

		listing(false, List.of(listed("a", 99)));
		Assertions.assertThrows(RetryLaterException.class, () -> handler.handle(job, note -> {
		}));
		Assertions.assertTrue(find("old").isEnabled(), "a partial listing disables nothing");
		BDDMockito.verify(health).record("bb", false, "The repository listing stopped early");
		Assertions.assertEquals(99, find("a").getLastCommitAt());

		listing(true, List.of(listed("a", 99)));
		handler.handle(job, note -> {
		});
		Assertions.assertFalse(find("old").isEnabled());
		BDDMockito.verify(health, BDDMockito.times(2)).record("bb", true, null);
	}

	@Test
	public void anEmptyListingDisablesNothing() throws Exception {
		listing(true, List.of(listed("a", 1)));
		handler.handle(job, note -> {
		});
		listing(true, List.of());
		handler.handle(job, note -> {
		});
		Assertions.assertTrue(find("a").isEnabled());
	}

	@Test
	public void repositoriesAWebhookNamedByDisplayNameMatchTheirSlugsAndStay() throws Exception {
		// A pull request webhook names a repository by its display name, a listing by its slug
		webhookRepository("Access-Review-Scripts");
		webhookRepository("Payments API");
		listing(true, List.of(listed("access-review-scripts", 10), listed("payments-api", 20),
				listed("new-one", 30)));

		handler.handle(job, note -> {
		});

		RepositoryEntity access = find("Access-Review-Scripts");
		Assertions.assertTrue(access.isEnabled(), "listed under its slug, so not gone");
		Assertions.assertEquals(10, access.getLastCommitAt(), "its catalog fields are filled");
		Assertions.assertTrue(find("Payments API").isEnabled());
		Assertions.assertEquals(20, find("Payments API").getLastCommitAt());
		Assertions.assertNull(find("payments-api"), "no second row for the slug");
		Assertions.assertEquals(3, repositories.count());
	}

	@Test
	public void aDuplicateUnderTheDisplayNameIsDisabledSoPlansStopScanningIt() throws Exception {
		// A webhook once stored "Payments API" and a sync inserted "payments-api" beside it
		webhookRepository("Payments API");
		webhookRepository("payments-api");
		listing(true, List.of(listed("payments-api", 20)));

		handler.handle(job, note -> {
		});

		Assertions.assertTrue(find("payments-api").isEnabled());
		Assertions.assertEquals(20, find("payments-api").getLastCommitAt());
		Assertions.assertFalse(find("Payments API").isEnabled(),
				"Bitbucket has no repository at that name: a branch scan of it can only fail");
	}

	@Test
	public void aSyncBringsBackRepositoriesAnEarlierSyncWronglyMarkedGone() throws Exception {
		RepositoryEntity access = webhookRepository("Access-Review-Scripts");
		access.setEnabled(false);
		repositories.saveAndFlush(access);
		listing(true, List.of(listed("access-review-scripts", 10)));

		handler.handle(job, note -> {
		});

		Assertions.assertTrue(find("Access-Review-Scripts").isEnabled());
	}

	@Test
	public void namesCompareAsTheSlugBitbucketMakesOfThem() {
		Assertions.assertEquals("access-review-scripts",
				RepoCatalogDao.nameKey("Access-Review-Scripts"));
		Assertions.assertEquals("payments-api", RepoCatalogDao.nameKey(" Payments API "));
		Assertions.assertEquals("my.repo_2", RepoCatalogDao.nameKey("my.repo_2"));
		Assertions.assertEquals("a-b", RepoCatalogDao.nameKey("A & B!"));
	}

	private RepositoryEntity webhookRepository(String name) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName(name);
		repo.setScanType(CodeScanType.PULL_REQUEST);
		repo.setEnabled(true);
		repo.setLastReviewedDate(System.currentTimeMillis());
		return repositories.saveAndFlush(repo);
	}

	@Test
	public void unchangedListingWritesNothing() {
		long now = System.currentTimeMillis();
		Assertions.assertEquals(1, catalog.upsertPage("bb", List.of(listed("a", 1)), null, now));
		Assertions.assertEquals(0, catalog.upsertPage("bb", List.of(listed("a", 1)), null, now));
		Assertions.assertEquals(1, catalog.upsertPage("bb", List.of(listed("a", 2)), null, now));
	}
}

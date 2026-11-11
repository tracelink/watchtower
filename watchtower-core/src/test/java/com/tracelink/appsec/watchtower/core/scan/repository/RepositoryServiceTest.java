package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

@ExtendWith(SpringExtension.class)
public class RepositoryServiceTest {

	RepositoryService repoService;

	@MockitoBean
	RepositoryRepository mockRepoRepo;

	@MockitoBean
	RulesetService mockRulesetService;

	@MockitoBean
	RepositoryStatusService mockStatuses;

	@MockitoBean
	RepoScanRepository mockScans;

	@MockitoBean
	RepoCatalogDao mockCatalog;

	@MockitoBean
	ApiIntegrationService mockIntegrations;

	@BeforeEach
	public void setup() {
		this.repoService = new RepositoryService(mockRepoRepo, mockRulesetService,
				mockStatuses, mockScans, mockCatalog, mockIntegrations);
	}

	@Test
	public void updateSetsOnlyWhatIsGivenAndValidates() throws Exception {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setTeam("old");
		repo.setOwnerName("someone");
		BDDMockito.when(mockRepoRepo.findById(5L)).thenReturn(Optional.of(repo));
		BDDMockito.when(mockRepoRepo.save(repo)).thenReturn(repo);

		repoService.update(5L, new RepositoryService.RepoEdit(null, " ", null, "PCI, sox", 1,
				true));

		Assertions.assertNull(repo.getTeam(), "a blank team clears it");
		Assertions.assertEquals("someone", repo.getOwnerName(), "a null owner is kept");
		Assertions.assertEquals(List.of("pci", "sox"), repo.getLabels());
		Assertions.assertEquals(1, repo.getCriticality());
		Assertions.assertTrue(repo.isScanningPaused());
		Assertions.assertThrows(IllegalArgumentException.class, () -> repoService.update(5L,
				new RepositoryService.RepoEdit(null, null, null, null, 9, null)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> repoService.update(5L,
				new RepositoryService.RepoEdit(null, null, null, "not a label!", null, null)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> repoService.update(6L,
				new RepositoryService.RepoEdit(null, null, null, null, null, true)));
	}

	@Test
	public void supportingRulesetsAreRefused() throws Exception {
		RulesetEntity supporting = new RulesetEntity();
		supporting.setDesignation(RulesetDesignation.SUPPORTING);
		BDDMockito.when(mockRulesetService.getRuleset(3L)).thenReturn(supporting);
		BDDMockito.when(mockRepoRepo.findById(5L))
				.thenReturn(Optional.of(new RepositoryEntity()));
		Assertions.assertThrows(RulesetException.class, () -> repoService.update(5L,
				new RepositoryService.RepoEdit(3L, null, null, null, null, null)));
	}

	@Test
	public void deleteRemovesScansThenRowsAndLeavesBusyRepositories() {
		RepositoryEntity idle = new RepositoryEntity();
		BDDMockito.when(mockScans.findRepositoriesBeingScanned(List.of(1L, 2L),
				List.of(ScanStatus.NOT_STARTED, ScanStatus.IN_PROGRESS)))
				.thenReturn(List.of(2L));
		BDDMockito.when(mockRepoRepo.findAllById(List.of(1L)))
				.thenReturn(List.of(idle));

		RepositoryService.DeleteResult result = repoService.delete(List.of(1L, 2L),
				"alice");

		Assertions.assertEquals(1, result.deleted());
		Assertions.assertEquals(1, result.busy());
		InOrder order = Mockito.inOrder(mockScans, mockRepoRepo);
		order.verify(mockScans).deleteByRepositoryIds(List.of(1L));
		order.verify(mockRepoRepo).deleteAllInBatch(List.of(idle));
	}

	@Test
	public void addingByHandRefusesOddSlugsAndUnknownRepositories() throws Exception {
		for (String bad : List.of("../../other-workspace", "..", ".", "a/b", "")) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> repoService
					.addManually("bb", bad, new RepositoryService.RepoEdit(null, null, null,
							null, null, null)), bad);
		}
		BDDMockito.verify(mockIntegrations, BDDMockito.never()).findByLabel(BDDMockito.any());

		ApiIntegrationEntity bb = Mockito.mock(ApiIntegrationEntity.class);
		IScmApi api = Mockito.mock(IScmApi.class);
		BDDMockito.when(mockIntegrations.findByLabel("bb")).thenReturn(bb);
		BDDMockito.when(bb.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(bb.createApi()).thenReturn(api);
		BDDMockito.when(api.getRepository("nope")).thenReturn(Optional.empty());

		IllegalArgumentException unknown = Assertions.assertThrows(
				IllegalArgumentException.class, () -> repoService.addManually("bb", "nope",
						new RepositoryService.RepoEdit(null, null, null, null, null, null)));
		Assertions.assertEquals("bb has no repository named nope", unknown.getMessage());
		BDDMockito.verify(mockCatalog, BDDMockito.never()).upsertPage(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any(), BDDMockito.anyLong());
	}

	@Test
	public void integrationNamesDifferingOnlyInCaseGroupTogether() {
		// Rows stored under "bitbucket" (V007 never renamed them) belong to "Bitbucket"
		RepositoryEntity lower = new RepositoryEntity();
		lower.setApiLabel("bitbucket");
		RepositoryEntity upper = new RepositoryEntity();
		upper.setApiLabel("Bitbucket");
		BDDMockito.when(mockRepoRepo.findByScanType(CodeScanType.PULL_REQUEST))
				.thenReturn(List.of(lower, upper));
		BDDMockito.when(mockRepoRepo.countByApiLabel()).thenReturn(List.<Object[]>of(
				new Object[] {"bitbucket", 3L}));

		Assertions.assertEquals(2, repoService.getAllRepos(CodeScanType.PULL_REQUEST)
				.getOrDefault("Bitbucket", List.of()).size());
		Assertions.assertEquals(3L, repoService.countsByIntegration().getOrDefault("Bitbucket", 0L),
				"the delete dialog offers to delete them");
	}

	@Test
	public void addingByHandInsertsLikeASyncThenAppliesTheEdit() throws Exception {
		ApiIntegrationEntity bb = Mockito.mock(ApiIntegrationEntity.class);
		IScmApi api = Mockito.mock(IScmApi.class);
		ScmRepository listed =
				new ScmRepository(
						"payments-api", "PAY", "main", 1L, 2L, "java");
		BDDMockito.when(mockIntegrations.findByLabel("bb")).thenReturn(bb);
		BDDMockito.when(bb.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(bb.createApi()).thenReturn(api);
		BDDMockito.when(api.getRepository("payments-api")).thenReturn(
				Optional.of(listed));
		RepositoryEntity inserted = new RepositoryEntity();
		BDDMockito.when(mockRepoRepo.findByApiLabelAndRepoName("bb", "payments-api"))
				.thenReturn(inserted);
		BDDMockito.when(mockRepoRepo.save(inserted)).thenReturn(inserted);

		repoService.addManually("bb", " payments-api ", new RepositoryService.RepoEdit(null,
				"checkout", null, null, null, null));

		BDDMockito.verify(mockCatalog).upsertPage(BDDMockito.eq("bb"),
				BDDMockito.eq(List.of(listed)), BDDMockito.any(), BDDMockito.anyLong());
		Assertions.assertEquals("checkout", inserted.getTeam());
	}

	@Test
	public void testSetRulesetForRepo() throws Exception {
		RepositoryEntity entity = new RepositoryEntity();
		BDDMockito
				.when(mockRepoRepo.findByApiLabelAndRepoName(BDDMockito.anyString(),
						BDDMockito.anyString()))
				.thenReturn(entity);
		RulesetEntity rulesetEntity = new RulesetEntity();
		rulesetEntity.setDesignation(RulesetDesignation.DEFAULT);
		BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyLong()))
				.thenReturn(rulesetEntity);
		repoService.setRulesetForRepo(1L, "ApiLabel", "");
		BDDMockito.verify(mockRepoRepo, Mockito.times(1)).saveAndFlush(entity);
		Assertions.assertEquals(rulesetEntity, entity.getRuleset());
	}

	@Test
	public void testSetRulesetForRepoSupporting() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RepositoryEntity entity = new RepositoryEntity();
					BDDMockito
							.when(mockRepoRepo.findByApiLabelAndRepoName(BDDMockito.anyString(),
									BDDMockito.anyString()))
							.thenReturn(entity);
					RulesetEntity rulesetEntity = new RulesetEntity();
					rulesetEntity.setDesignation(RulesetDesignation.SUPPORTING);
					BDDMockito.when(mockRulesetService.getRuleset(BDDMockito.anyLong()))
							.thenReturn(rulesetEntity);
					repoService.setRulesetForRepo(1L, "ApiLabel", "");
				});
	}

	@Test
	public void testUpsertRepoUpdate() {
		long originalRevDate = 0L;
		RepositoryEntity entity = new RepositoryEntity();
		entity.setLastReviewedDate(originalRevDate);
		BDDMockito
				.when(mockRepoRepo.findByApiLabelAndRepoName(BDDMockito.anyString(),
						BDDMockito.anyString()))
				.thenReturn(entity);
		repoService.upsertRepo(CodeScanType.PULL_REQUEST, ApiType.BITBUCKET_CLOUD.getTypeName(),
				"");
		Assertions.assertTrue(entity.getLastReviewedDate() > originalRevDate);
	}

	@Test
	public void testUpsertRepoInsert() {
		String type = ApiType.BITBUCKET_CLOUD.getTypeName();
		String repoName = "foobar";
		BDDMockito
				.when(mockRepoRepo.findByApiLabelAndRepoName(BDDMockito.anyString(),
						BDDMockito.anyString()))
				.thenReturn(null);
		repoService.upsertRepo(CodeScanType.PULL_REQUEST, type, repoName);

		ArgumentCaptor<RepositoryEntity> entityCaptor =
				ArgumentCaptor.forClass(RepositoryEntity.class);
		BDDMockito.verify(mockRepoRepo).save(entityCaptor.capture());

		RepositoryEntity entity = entityCaptor.getValue();
		Assertions.assertEquals(type, entity.getApiLabel());
		Assertions.assertEquals(repoName, entity.getRepoName());
		Assertions.assertTrue(entity.getLastReviewedDate() > 0L);
	}

}

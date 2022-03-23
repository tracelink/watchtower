package com.tracelink.appsec.watchtower.core.scan.scm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiType;

@ExtendWith(SpringExtension.class)
public class RepositoryServiceTest {

	ScmRepositoryService repoService;

	@MockBean
	ScmRepositoryRepository mockRepoRepo;

	@MockBean
	RulesetService mockRulesetService;

	@BeforeEach
	public void setup() {
		this.repoService = new ScmRepositoryService(mockRepoRepo, mockRulesetService);
	}

	@Test
	public void testSetRulesetForRepo() throws Exception {
		ScmRepositoryEntity entity = new ScmRepositoryEntity();
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
					ScmRepositoryEntity entity = new ScmRepositoryEntity();
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
		ScmRepositoryEntity entity = new ScmRepositoryEntity();
		entity.setLastReviewedDate(originalRevDate);
		BDDMockito
				.when(mockRepoRepo.findByApiLabelAndRepoName(BDDMockito.anyString(),
						BDDMockito.anyString()))
				.thenReturn(entity);
		repoService.upsertRepo(ApiType.BITBUCKET_CLOUD.getTypeName(), "");
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
		repoService.upsertRepo(type, repoName);

		ArgumentCaptor<ScmRepositoryEntity> entityCaptor =
				ArgumentCaptor.forClass(ScmRepositoryEntity.class);
		BDDMockito.verify(mockRepoRepo).save(entityCaptor.capture());

		ScmRepositoryEntity entity = entityCaptor.getValue();
		Assertions.assertEquals(type, entity.getApiLabel());
		Assertions.assertEquals(repoName, entity.getRepoName());
		Assertions.assertTrue(entity.getLastReviewedDate() > 0L);
	}

}

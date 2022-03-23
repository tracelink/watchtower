package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.Date;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.api.ApiType;

public class RepositoryEntityTest {

	@Test
	public void testDAO() {
		long lastReviewedDate = System.currentTimeMillis();
		String apiLabel = ApiType.BITBUCKET_CLOUD.getTypeName();
		String repoName = "repoName";
		RulesetEntity rulesetEntity = new RulesetEntity();
		rulesetEntity.setName("Default");

		ScmRepositoryEntity entity = new ScmRepositoryEntity();
		entity.setApiLabel(apiLabel);
		entity.setLastReviewedDate(lastReviewedDate);
		entity.setRepoName(repoName);
		entity.setRuleset(rulesetEntity);

		Assertions.assertEquals(lastReviewedDate, entity.getLastReviewedDate());
		Assertions.assertEquals(new Date(lastReviewedDate), entity.getLastReviewedDateAsDate());
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(repoName, entity.getRepoName());
		Assertions.assertEquals(rulesetEntity, entity.getRuleset());
	}

}

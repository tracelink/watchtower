package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.RepositorySlug;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;

/**
 * Writes the repository catalog with Hibernate: one read of the integration's repositories per
 * sync, an update only for rows whose catalog fields changed, an insert only for new
 * repositories. A sync of an unchanged workspace therefore writes nothing.
 *
 * @author Watchtower
 */
@Repository
public class RepoCatalogDao {

	private static final Logger LOG = LoggerFactory.getLogger(RepoCatalogDao.class);

	private static final String SCAN_TYPE = CodeScanType.PULL_REQUEST.getTypeName();


 private final LedgerRepository records;
 private final TransactionTemplate transaction;
 public RepoCatalogDao(LedgerRepository records,PlatformTransactionManager tm) {this.records=records;this.transaction=new TransactionTemplate(tm);}

	/**
	 * The key a repository is matched on: its slug. A listing names a repository by its slug
	 * ({@code payments-api}) but a pull request webhook by its display name
	 * ({@code Payments-API}, {@code Payments API}), and MySQL compares names ignoring case, so
	 * names are compared as the slug Bitbucket makes of them.
	 */
	public static String nameKey(String name) {
		return RepositorySlug.of(name);
	}

	/**
	 * @param apiLabel the integration
	 * @return the integration's repositories by {@link #nameKey}. Of two rows with one key (a
	 *         pull request webhook once stored "Payments API" next to the listed
	 *         "payments-api"), the one named by its slug is kept and the other is shadowed
	 */
	public Catalog rows(String apiLabel) {
		Map<String, CatalogRow> rows = new HashMap<>();
		List<CatalogRow> shadowed = new ArrayList<>();
  for(var values:records.maps("SELECT r.id AS id,r.repoName AS name,r.projectKey AS project,r.defaultBranch AS branch,COALESCE(r.lastCommitAt,0) AS commit_time,COALESCE(r.sizeBytes,0) AS size,r.primaryLanguage AS language,r.enabled AS enabled FROM RepositoryEntity r WHERE r.apiLabel=?1 AND r.scanType=?2",0,Integer.MAX_VALUE,apiLabel,CodeScanType.PULL_REQUEST)) {
   CatalogRow row=new CatalogRow(((Number)values.get("id")).longValue(),(String)values.get("name"),(String)values.get("project"),(String)values.get("branch"),((Number)values.get("commit_time")).longValue(),((Number)values.get("size")).longValue(),(String)values.get("language"),(Boolean)values.get("enabled"));
   String key=nameKey(row.name());CatalogRow kept=rows.get(key);
   if(kept==null)rows.put(key,row);
   else if(row.isSlugNamed()&&!kept.isSlugNamed()){shadowed.add(kept);rows.put(key,row);}
   else shadowed.add(row);
  }
		return new Catalog(rows, shadowed);
	}

	/**
	 * An integration's repositories as a sync matches them.
	 *
	 * @param byKey    one row per {@link #nameKey}
	 * @param shadowed the other rows with a key already taken: duplicates under a display name
	 */
	public record Catalog(Map<String, CatalogRow> byKey, List<CatalogRow> shadowed) {
	}

	/**
	 * Inserts new repositories and updates changed ones from one listing page, reading the
	 * integration's repositories first. A sync reads them once instead (see
	 * {@link #upsertPage(String, List, Map, Long, long)}).
	 */
	public int upsertPage(String apiLabel, List<ScmRepository> page, Long defaultRulesetId,
			long now) {
		return page.isEmpty() ? 0
				: upsertPage(apiLabel, page, rows(apiLabel).byKey(), defaultRulesetId, now);
	}

	/**
	 * Inserts new repositories and updates changed ones from one listing page.
	 *
	 * @param apiLabel         the integration
	 * @param page             the listed repositories
	 * @param existing         the integration's repositories, from {@link #rows(String)}
	 * @param defaultRulesetId the ruleset new repositories get, as a first pull request would
	 *                         give them; null if there is no default
	 * @param now              the sync time
	 * @return how many rows were inserted or changed
	 */
	public int upsertPage(String apiLabel, List<ScmRepository> page,
			Map<String, CatalogRow> existing, Long defaultRulesetId, long now) {
		int written = 0;
		for (ScmRepository listed : page) {
			CatalogRow row = existing.get(nameKey(listed.slug()));
			if (row == null) {
				written += insert(apiLabel, listed, defaultRulesetId, now);
			} else if (!row.matches(listed)) {
    transaction.executeWithoutResult(tx->{var entity=records.lock(RepositoryEntity.class,row.id());if(entity!=null)catalogFields(entity,listed,now);});
				written++;
			}
		}
		return written;
	}

	/**
	 * Marks repositories the SCM no longer lists as disabled, the same state downtime recovery
	 * gives a deleted repository. A pull request webhook enables a repository again.
	 *
	 * @param ids the repositories to disable
	 * @return how many were disabled
	 */
	public int disable(Collection<Long> ids) {
		if (ids.isEmpty()) {
			return 0;
		}
		return records.update("UPDATE RepositoryEntity r SET r.configurationVersion=r.configurationVersion+1,r.enabled=FALSE WHERE r.id IN ?1",ids);
	}

	/**
	 * Points a repository at its latest finished scan, so lists show its last result with a
	 * primary key join.
	 */
	public void setLastScan(long repositoryId, long scanId) {
		records.update("UPDATE RepositoryEntity r SET r.configurationVersion=r.configurationVersion+1,r.lastRepoScanId=?1 WHERE r.id=?2",scanId,repositoryId);
	}

 private int insert(String apiLabel,ScmRepository listed,Long defaultRulesetId,long now) {
  try {return transaction.execute(tx->{
   records.lockScope("ruleset-configuration");
   // A webhook may have created the row after the initial catalog read.
   if(!records.list(RepositoryEntity.class,"SELECT r FROM RepositoryEntity r WHERE r.apiLabel=?1 AND r.repoName=?2",0,1,apiLabel,listed.slug()).isEmpty())return 0;
   var entity=new RepositoryEntity();entity.setScanType(CodeScanType.PULL_REQUEST);entity.setApiLabel(apiLabel);entity.setRepoName(listed.slug());
   if(defaultRulesetId!=null)entity.setRuleset(records.find(RulesetEntity.class,defaultRulesetId));
   catalogFields(entity,listed,now);records.insert(entity);return 1;
  });}catch(DataIntegrityViolationException concurrentCreate){
   // The transaction has rolled back before handling a unique-key race.
   if(records.list(RepositoryEntity.class,"SELECT r FROM RepositoryEntity r WHERE r.apiLabel=?1 AND r.repoName=?2",0,1,apiLabel,listed.slug()).isEmpty())throw concurrentCreate;
   LOG.debug("Repository {} of {} was created concurrently",listed.slug(),apiLabel);return 0;
  }
 }
 private void catalogFields(RepositoryEntity entity,ScmRepository listed,long now){
  entity.setProjectKey(listed.projectKey());entity.setDefaultBranch(listed.defaultBranch());entity.setLastCommitAt(listed.updatedOn());
  entity.setSizeBytes(listed.sizeBytes());entity.setPrimaryLanguage(listed.language());entity.setScmSyncedAt(now);entity.setEnabled(true);
 }

	/**
	 * The catalog fields of an existing row, to tell whether a listing changed anything.
	 */
	public record CatalogRow(long id, String name, String projectKey, String defaultBranch,
			long lastCommitAt, long sizeBytes, String language, boolean enabled) {

		/** @return true if the row is named by its slug, as a listing names it */
		boolean isSlugNamed() {
			return name.equals(nameKey(name));
		}

		boolean matches(ScmRepository listed) {
			return enabled && Objects.equals(projectKey, listed.projectKey())
					&& Objects.equals(defaultBranch, listed.defaultBranch())
					&& lastCommitAt == listed.updatedOn() && sizeBytes == listed.sizeBytes()
					&& Objects.equals(language, listed.language());
		}
	}
}

package com.tracelink.appsec.watchtower.core.persistence;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.io.StringReader;
import java.util.*;
import org.junit.jupiter.api.*;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.repository.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.job.*;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class LegacyOrmPersistenceTest {
 R1Database database;
 @BeforeEach void setup(){database=new R1Database();}
 @AfterEach void close(){database.close();}
 @Test void catalogChangesPreserveHumanPolicyAndSkipUnchangedRepositories(){
  var catalog=new RepoCatalogDao(database.records,database.tx);
  var listing=new ScmRepository("payments-api","PAY","main",100L,200L,"java");
  assertEquals(1,catalog.upsertPage("SCM",List.of(listing),null,300));
  var row=catalog.rows("SCM").byKey().get("payments-api");
  new TransactionTemplate(database.tx).executeWithoutResult(tx->{var repo=database.records.lock(RepositoryEntity.class,row.id());repo.setTeam("Security");repo.setCriticality(1);repo.setScanningPaused(true);});
  assertEquals(0,catalog.upsertPage("SCM",List.of(listing),null,400));
  assertEquals(1,catalog.upsertPage("SCM",List.of(new ScmRepository("payments-api","PAY","release",500L,600L,"java")),null,700));
  var repo=database.records.find(RepositoryEntity.class,row.id());assertEquals("Security",repo.getTeam());assertEquals(1,repo.getCriticality());assertTrue(repo.isScanningPaused());assertEquals("release",repo.getDefaultBranch());
  catalog.setLastScan(row.id(),99);catalog.disable(List.of(row.id()));repo=database.records.find(RepositoryEntity.class,row.id());assertEquals(99L,repo.getLastRepoScanId());assertFalse(repo.isEnabled());assertTrue(repo.isScanningPaused());
 }
 @Test void csvUpdatesOnlyProvidedFieldsAndKeepsDuplicateRowsInFileOrder()throws Exception{
  var catalog=new RepoCatalogDao(database.records,database.tx);catalog.upsertPage("SCM",List.of(new ScmRepository("payments-api","PAY","main",0L,0L,"java")),null,1);
  var row=catalog.rows("SCM").byKey().get("payments-api");
  new TransactionTemplate(database.tx).executeWithoutResult(tx->{var repo=database.records.lock(RepositoryEntity.class,row.id());repo.setTeam("Existing team");repo.setOwnerName("old owner");repo.setCriticality(2);repo.setScanningPaused(true);});
  var rulesets=mock(RulesetService.class);when(rulesets.getRulesets()).thenReturn(List.of());
  var csv=database.service(new RepositoryCsvService(mock(RepositoryRepository.class),mock(RepositoryStatusService.class),rulesets,database.records));
  var result=csv.importCsv(CodeScanType.PULL_REQUEST,"SCM",new StringReader("repo,owner\npayments-api,new owner\nmissing,skip\npayments-api,final owner\n"),"reviewer");
  assertEquals(2,result.updated());assertEquals(1,result.skipped());var repo=database.records.find(RepositoryEntity.class,row.id());
  assertEquals("final owner",repo.getOwnerName());assertEquals("Existing team",repo.getTeam());assertEquals(2,repo.getCriticality());assertTrue(repo.isScanningPaused());
 }
 @Test void sharedModulePolicyPreservesRulesAndVersionsAcrossInstances(){
  var repository=database.repository(com.tracelink.appsec.watchtower.core.module.ModuleSettingRepository.class);
  var first=database.service(new com.tracelink.appsec.watchtower.core.module.ModuleControlService(repository));
  var second=database.service(new com.tracelink.appsec.watchtower.core.module.ModuleControlService(repository));
  org.springframework.test.util.ReflectionTestUtils.setField(first,"records",database.records);
  first.register("ExternalPlugin");first.register("externalplugin");assertTrue(second.enabled("ExternalPlugin"));
  assertTrue(first.enabled("REGEX"));assertFalse(first.enabled("Opengrep"));assertTrue(first.enabled("ExternalPlugin"));
  database.seedRule(9,"a".repeat(64));String original=first.fingerprint();
  first.change("regex",false,0,"engineer");assertFalse(second.enabled("Regex"));assertEquals(1,second.policy("regex").version());
  assertNotEquals(original,second.fingerprint());assertThrows(RuntimeException.class,()->second.change("regex",true,0,"stale user"));
  assertThrows(RuntimeException.class,()->first.requireEnabled("regex"));assertThrows(RuntimeException.class,()->first.change("unknown",false,0,"user"));
  second.change("regex",true,1,"engineer");assertTrue(first.enabled("regex"));assertNotEquals(original,first.fingerprint());
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM rules WHERE rule_id=9",Integer.class));
 }
 @Test void boundedJobCleanupUsesJpaAndKeepsUnfinishedJobs(){
  var old=new AsyncJobEntity();old.setType(AsyncJobType.RULE_CANDIDATE_TEST);old.setStatus(AsyncJobStatus.DONE);old.setCreatedAt(1);org.springframework.test.util.ReflectionTestUtils.setField(old,"finishedAt",2L);database.records.insert(old);
  var queued=new AsyncJobEntity();queued.setType(AsyncJobType.RULE_CANDIDATE_TEST);queued.setStatus(AsyncJobStatus.QUEUED);queued.setCreatedAt(1);database.records.insert(queued);
  var jobs=database.repository(AsyncJobRepository.class);
  Integer deleted=new TransactionTemplate(database.tx).execute(tx->jobs.deleteFinishedBefore(10L));assertEquals(1,deleted.intValue());
  assertNotNull(database.records.find(AsyncJobEntity.class,queued.getId()));assertNull(database.records.find(AsyncJobEntity.class,old.getId()));
 }
}

package com.tracelink.appsec.watchtower.core.assistant.assessment;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.repository.*;

/** Findings resolve to rule, repository, pinned commit, path and line - or a plain reason. */
class FindingLocatorTest {
 LedgerRepository records=mock(LedgerRepository.class);RepoScanRepository scans=mock(RepoScanRepository.class);RepoScanReportService reports=mock(RepoScanReportService.class);
 RepositoryRepository repositories=mock(RepositoryRepository.class);FindingLocator locator=new FindingLocator(records,scans,reports,repositories);
 RepositoryEntity repo=mock(RepositoryEntity.class);
 PullRequestViolationEntity violation(String commit){
  var v=mock(PullRequestViolationEntity.class);var scan=mock(PullRequestScanEntity.class);var container=mock(PullRequestContainerEntity.class);
  when(v.getScan()).thenReturn(scan);when(scan.getId()).thenReturn(5L);when(scan.getCommitHash()).thenReturn(commit);when(scan.getContainer()).thenReturn(container);
  when(container.getApiLabel()).thenReturn("Bitbucket");when(container.getRepoName()).thenReturn("Payments API");
  when(v.getExecutionRuleId()).thenReturn(7L);when(v.getRuleRevision()).thenReturn("a".repeat(64));when(v.getFileName()).thenReturn("src/A.java");when(v.getLineNum()).thenReturn(88);
  return v;
 }
 @Test void pullRequestFindingsMatchTheCatalogBySlugAndNeedARecordedCommit(){
  when(repo.getRepoName()).thenReturn("payments-api");
  when(records.list(eq(RepositoryEntity.class),anyString(),anyInt(),anyInt(),eq("bitbucket"))).thenReturn(List.of(repo));
  var v=violation("c".repeat(40));when(records.find(PullRequestViolationEntity.class,9L)).thenReturn(v);
  var located=locator.locate("pull_request",5,"9");
  assertNull(located.unavailable());assertSame(repo,located.repository());assertEquals("src/A.java",located.path());assertEquals(88,located.line());assertEquals(7L,located.ruleId());
  // an abbreviated commit is located; the evidence step completes it
  var abbreviated=violation("c".repeat(12));when(records.find(PullRequestViolationEntity.class,11L)).thenReturn(abbreviated);
  assertNull(locator.locate("pull_request",5,"11").unavailable());
  var uncommitted=violation(null);when(records.find(PullRequestViolationEntity.class,10L)).thenReturn(uncommitted);
  assertTrue(locator.locate("pull_request",5,"10").unavailable().contains("commit was not recorded"));
  assertThrows(ResponseStatusException.class,()->locator.locate("pull_request",6,"9"),"the finding must belong to the scan");
  assertThrows(IllegalArgumentException.class,()->locator.locate("pull_request",5,"not-a-number"));
 }
 @Test void uploadsExpiredReportsAndUncataloguedRepositoriesExplainThemselves(){
  assertTrue(locator.locate("upload",3,"1").unavailable().contains("not kept"));
  var scan=mock(RepoScanEntity.class);when(scans.findById(4L)).thenReturn(Optional.of(scan));when(reports.getReport(scan)).thenReturn(Optional.empty());
  assertTrue(locator.locate("repository",4,"k").unavailable().contains("expired"));
  // The scan only holds a lazy reference; the locator must load the catalog row itself
  var reference=mock(RepositoryEntity.class);when(reference.getApiLabel()).thenReturn("Bitbucket");when(reference.getRepoName()).thenReturn("payments-api");
  when(repositories.findByApiLabelAndRepoName("Bitbucket","payments-api")).thenReturn(repo);
  when(scan.getRepository()).thenReturn(reference);when(scan.getCommitHash()).thenReturn("d".repeat(40));
  var finding=new RepoScanReport.Finding("xss","HIGH","web/App.java",12,"m","f",false,null,new RuleExecutionIdentity(7L,"PMD","b".repeat(64),null,null),null,null,"k");
  when(reports.getReport(scan)).thenReturn(Optional.of(new RepoScanReport(RepoScanReport.SCHEMA,4,"Bitbucket","payments-api","main","d".repeat(40),"default",List.of(finding),List.of(),List.of(),1,null)));
  var located=locator.locate("repository",4,"k");assertNull(located.unavailable());assertSame(repo,located.repository());assertEquals("web/App.java",located.path());assertEquals("b".repeat(64),located.revision());
  var uncatalogued=violation("c".repeat(40));when(records.find(PullRequestViolationEntity.class,9L)).thenReturn(uncatalogued);
  assertTrue(locator.locate("pull_request",5,"9").unavailable().contains("not in Watchtower's catalog"));
  assertThrows(IllegalArgumentException.class,()->locator.locate("image",5,"9"));
 }
}

package com.tracelink.appsec.watchtower.core.feedback;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.persistence.MissedVulnerabilityCaseEntity;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import com.tracelink.appsec.watchtower.core.rule.variant.VariantSearchService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.*;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** R5.3: missed case → deterministic regression proposal → reviewed fixtures → variant search. */
class MissedCaseWorkflowTest {
 static final String CASE="0f0e0d0c-0b0a-4900-8000-000000000001",VULN="a".repeat(40),FIX="b".repeat(40);
 static final String BEFORE="class OrderDao {\n  String q(String id) {\n    return \"SELECT * FROM orders WHERE id = \" + id;\n  }\n}\n";
 static final String AFTER="class OrderDao {\n  String q(String id) {\n    return \"SELECT * FROM orders WHERE id = ?\";\n  }\n}\n";
 MissedVulnerabilityService cases=mock(MissedVulnerabilityService.class);AssistantSourceTools source=mock(AssistantSourceTools.class);
 RuleCandidateService candidates=mock(RuleCandidateService.class);AssistantAccess access=mock(AssistantAccess.class);IScmApi api=mock(IScmApi.class);
 RepositoryEntity repo=mock(RepositoryEntity.class);

 MissedVulnerabilityCaseEntity missed(String fixed){
  var c=new MissedVulnerabilityCaseEntity();c.caseId=CASE;c.repositoryId=7L;c.repositoryName="orders-service";c.commitHash=VULN;c.fixedCommitHash=fixed;
  c.affectedPath="src/main/java/OrderDao.java";c.firstLine=3;c.cwe="CWE-89";c.ruleId=42L;return c;
 }
 @BeforeEach void setup(){
  when(repo.getId()).thenReturn(7L);when(repo.getRepoName()).thenReturn("orders-service");when(repo.getApiLabel()).thenReturn("bb");
  when(repo.getDefaultBranch()).thenReturn("main");when(repo.getScanType()).thenReturn(CodeScanType.REPOSITORY);
  when(source.target(anyString(),anyLong())).thenReturn(new AssistantSourceTools.Target(repo,api));
 }

 @Test void lineDiffIsDeterministicAndFindsChangedRanges(){
  assertEquals(List.of(),LineDiff.changes(List.of("a","b"),List.of("a","b")));
  assertEquals(List.of(new LineDiff.Change(2,2,2,2)),LineDiff.changes(List.of("a","x","c"),List.of("a","y","c")));
  assertEquals(List.of(new LineDiff.Change(2,1,2,3)),LineDiff.changes(List.of("a","c"),List.of("a","n1","n2","c")),"pure insertion has an empty old range");
  assertEquals(List.of(new LineDiff.Change(2,3,2,1)),LineDiff.changes(List.of("a","d1","d2","c"),List.of("a","c")),"pure deletion has an empty new range");
  assertEquals(List.of(new LineDiff.Change(2,2,2,2),new LineDiff.Change(4,4,4,4)),LineDiff.changes(List.of("a","x","b","y","c"),List.of("a","X","b","Y","c")));
  var big=new ArrayList<String>();var other=new ArrayList<String>();for(int i=0;i<2000;i++){big.add("o"+i);other.add("n"+i);}
  assertEquals(List.of(new LineDiff.Change(1,2000,1,2000)),LineDiff.changes(big,other),"an oversized middle is one range, never guessed");
 }
 @Test void proposalComparesBothCommitsRedactsTheExcerptAndExplainsEveryOutcome(){
  var service=new RegressionProposalService(cases,source,candidates,access);
  when(cases.find(CASE,"reviewer")).thenReturn(missed(FIX));
  when(api.getFileContentAtCommit("orders-service",VULN,"src/main/java/OrderDao.java")).thenReturn(BEFORE.replace("class OrderDao {","class OrderDao { // password=hunter2secret"));
  when(api.getFileContentAtCommit("orders-service",FIX,"src/main/java/OrderDao.java")).thenReturn(AFTER);
  var p=service.propose(CASE,"reviewer");
  assertEquals("READY",p.get("status"));assertEquals(true,p.get("recorded_line_changed"));
  @SuppressWarnings("unchecked") var fixtures=(List<Map<String,Object>>)p.get("fixtures");
  assertEquals(List.of("MATCH","NO_MATCH"),fixtures.stream().map(f->f.get("expected")).toList());
  assertEquals("missed/"+CASE+"/vulnerable-OrderDao.java",fixtures.get(0).get("reference"));
  assertEquals(RuleDefinitionHistory.hash(AFTER),fixtures.get(1).get("sha256"),"hashes cover the exact file bytes");
  @SuppressWarnings("unchecked") var excerpt=(List<Map<String,Object>>)p.get("excerpt");
  assertTrue(excerpt.stream().anyMatch(l->Boolean.TRUE.equals(l.get("recorded"))&&Boolean.TRUE.equals(l.get("changed"))));
  assertTrue(excerpt.stream().noneMatch(l->String.valueOf(l.get("text")).contains("hunter2secret")),"secrets never reach the browser");
  assertEquals(p,service.propose(CASE,"reviewer"),"same case and commits, same proposal");

  when(api.getFileContentAtCommit("orders-service",FIX,"src/main/java/OrderDao.java")).thenReturn(BEFORE.replace("class OrderDao {","class OrderDao { // password=hunter2secret"));
  assertEquals("NO_CHANGE",service.propose(CASE,"reviewer").get("status"));
  when(api.getFileContentAtCommit("orders-service",FIX,"src/main/java/OrderDao.java")).thenReturn(null);
  var removed=service.propose(CASE,"reviewer");assertEquals("FIXED_FILE_REMOVED",removed.get("status"));assertEquals(1,((List<?>)removed.get("fixtures")).size());
  when(api.getFileContentAtCommit("orders-service",VULN,"src/main/java/OrderDao.java")).thenReturn("x".repeat(70_000));
  assertEquals("TOO_LARGE",service.propose(CASE,"reviewer").get("status"));
  when(api.getFileContentAtCommit("orders-service",VULN,"src/main/java/OrderDao.java")).thenReturn(null);
  assertEquals("FILE_UNAVAILABLE",service.propose(CASE,"reviewer").get("status"));
  when(cases.find(CASE,"reviewer")).thenReturn(missed(null));when(api.getFileContentAtCommit("orders-service",VULN,"src/main/java/OrderDao.java")).thenReturn(BEFORE);
  assertEquals("NO_FIXED_COMMIT",service.propose(CASE,"reviewer").get("status"));
  // A multi-line private key above the vulnerable line is masked without shifting line numbers.
  var keyed=missed(FIX);keyed.firstLine=6;when(cases.find(CASE,"reviewer")).thenReturn(keyed);
  String key="-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretmaterial\n-----END RSA PRIVATE KEY-----\n";
  when(api.getFileContentAtCommit("orders-service",VULN,"src/main/java/OrderDao.java")).thenReturn(key+BEFORE);
  when(api.getFileContentAtCommit("orders-service",FIX,"src/main/java/OrderDao.java")).thenReturn(key+AFTER);
  @SuppressWarnings("unchecked") var lines=(List<Map<String,Object>>)service.propose(CASE,"reviewer").get("excerpt");
  var recorded=lines.stream().filter(l->Boolean.TRUE.equals(l.get("recorded"))).findFirst().orElseThrow();
  assertTrue(String.valueOf(recorded.get("text")).contains("SELECT"),"line 6 is still the query line");assertEquals(true,recorded.get("changed"));
  assertTrue(lines.stream().noneMatch(l->String.valueOf(l.get("text")).contains("MIIEsecret")));
  assertTrue(RuleCandidateTester.relative("src/a..b.js"));assertFalse(RuleCandidateTester.relative("src/../etc/passwd"));
  assertFalse(RuleCandidateTester.relative("/etc/passwd"));assertFalse(RuleCandidateTester.relative("C:\\x"));assertFalse(RuleCandidateTester.relative("src//x"));
 }
 @Test void savingCreatesReviewedRegressionFixturesOnlyForAUsableProposal(){
  var service=new RegressionProposalService(cases,source,candidates,access);
  when(cases.find(CASE,"reviewer")).thenReturn(missed(FIX));when(cases.find(CASE,"viewer")).thenReturn(missed(FIX));
  when(api.getFileContentAtCommit(eq("orders-service"),eq(VULN),anyString())).thenReturn(BEFORE);when(api.getFileContentAtCommit(eq("orders-service"),eq(FIX),anyString())).thenReturn(AFTER);
  when(candidates.fixture(any(),eq("reviewer"))).thenReturn("f1","f2");
  assertEquals(List.of("f1","f2"),service.save(CASE,42,"reviewer"));
  when(candidates.fixtures(42)).thenReturn(List.of(Map.of("fixture_ref","missed/"+CASE+"/vulnerable-OrderDao.java"),Map.of("fixture_ref","missed/"+CASE+"/fixed-OrderDao.java")));
  assertEquals(List.of(),service.save(CASE,42,"reviewer"),"saving again does not duplicate fixtures");
  var saved=ArgumentCaptor.forClass(RuleCandidateService.Fixture.class);verify(candidates,times(2)).fixture(saved.capture(),eq("reviewer"));
  assertEquals(List.of("MATCH","NO_MATCH"),saved.getAllValues().stream().map(RuleCandidateService.Fixture::expected).toList());
  assertTrue(saved.getAllValues().stream().allMatch(f->f.ruleId()==42&&"REGRESSION".equals(f.cohort())&&("missed-case/"+CASE).equals(f.evidenceReference())));
  doThrow(new AccessDeniedException("no")).when(access).require("viewer","Rule Modify");
  assertThrows(AccessDeniedException.class,()->service.save(CASE,42,"viewer"));
  when(api.getFileContentAtCommit(eq("orders-service"),eq(FIX),anyString())).thenReturn(BEFORE);
  assertThrows(IllegalArgumentException.class,()->service.save(CASE,42,"reviewer"));
 }

 R1Database database;VariantSearchService searches;RuleCandidateTester tester=mock(RuleCandidateTester.class);AsyncJobService jobs=mock(AsyncJobService.class);
 List<String> progress=new ArrayList<>();
 @TempDir Path temp;
 void searchSetup()throws Exception{
  database=new R1Database();var rules=mock(RuleService.class);var entity=mock(RuleEntity.class);
  var dto=new MockCustomRuleDto();dto.setName("Concatenated SQL");dto.setMessage("SQL built from input");dto.setAuthor("appsec");dto.setPriority(RulePriority.HIGH);
  when(entity.toDto()).thenReturn((RuleDto)dto);when(rules.getRule(42)).thenReturn(entity);
  when(tester.available()).thenReturn(true);
  when(jobs.enqueue(eq(AsyncJobType.VARIANT_SEARCH),anyString(),anyString(),anyString())).thenReturn(Optional.of(new AsyncJobEntity()));
  when(api.getBranch("orders-service","main")).thenReturn(Optional.of(new ScmBranch("main","c".repeat(40),0)));
  doAnswer(inv->{Path dir=inv.getArgument(2);Files.createDirectories(dir.resolve("src"));Files.writeString(dir.resolve("src/InvoiceDao.java"),"query");return null;})
   .when(api).downloadSource(eq("orders-service"),anyString(),any(),eq(SourceDownloadLimits.SCAN));
  @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<AsyncJobService> provider=mock(org.springframework.beans.factory.ObjectProvider.class);when(provider.getObject()).thenReturn(jobs);
  searches=database.service(new VariantSearchService(database.records,source,access,rules,tester,cases,provider,database.tx,temp.resolve("work").toString()));
 }
 @AfterEach void close(){if(database!=null)database.close();}
 @Test void variantSearchPinsEachRepositoryStoresOnlyLocationsAndResumes()throws Exception{
  searchSetup();when(cases.find(CASE,"reviewer")).thenReturn(missed(FIX));
  var request=ArgumentCaptor.forClass(RuleTestSuite.SearchRequest.class);
  when(tester.search(request.capture())).thenAnswer(inv->{
   Path root=Path.of(((RuleTestSuite.SearchRequest)inv.getArgument(0)).directory());assertTrue(Files.exists(root.resolve("src/InvoiceDao.java")),"the engine sees the pinned checkout");
   return new RuleTestSuite.SearchResult("COMPLETE",List.of(new RuleTestSuite.Location("src/InvoiceDao.java",88)),0,false,"identity");});
  assertThrows(IllegalArgumentException.class,()->searches.start(new VariantSearchService.Start(CASE,null,null,List.of()),"reviewer"));
  assertThrows(IllegalArgumentException.class,()->searches.start(new VariantSearchService.Start(CASE,null,null,java.util.stream.LongStream.range(0,26).boxed().toList()),"reviewer"));
  String id=searches.start(new VariantSearchService.Start(CASE,null,null,List.of(7L)),"reviewer");
  verify(jobs).enqueue(AsyncJobType.VARIANT_SEARCH,id,"variant-search:"+id,"reviewer");
  assertEquals("QUEUED",searches.get(id,"reviewer").get("status"));
  searches.run(id,progress::add);
  var result=searches.get(id,"reviewer");assertEquals("DONE",result.get("status"));assertEquals(1L,((Number)result.get("total_matches")).longValue());
  @SuppressWarnings("unchecked") var repo=((List<Map<String,Object>>)result.get("repositories")).getFirst();
  assertEquals("c".repeat(40),repo.get("commit"));assertEquals("COMPLETE",repo.get("status"));assertEquals(RuleDefinitionHistory.hash("identity"),repo.get("engine_identity"),"the engine that produced the result is recorded");
  assertEquals(List.of(Map.of("path","src/InvoiceDao.java","line",88)),repo.get("locations"));
  assertEquals("mock",request.getValue().module());assertEquals(RuleDefinitionHistory.hash(request.getValue().definition()),result.get("definition_hash"),"the exact definition run is recorded");
  assertEquals(List.of("Searching repository 1 of 1"),progress);
  try(var left=Files.list(temp.resolve("work"))){assertEquals(0,left.count(),"the checkout is deleted after the search");}
  searches.run(id,progress::add);verify(tester,times(1)).search(any());
  assertEquals(1,searches.forCase(CASE,"reviewer").size());
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class),"normal findings and labels are untouched");
 }
 @Test void revokedGrantsAndUnavailableSourceAreReportedPerRepository()throws Exception{
  searchSetup();
  String revoked=searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer");
  doThrow(new AccessDeniedException("revoked")).when(access).require("reviewer","Rule Modify");
  searches.run(revoked,progress::add);
  var view=searches.get(revoked,"reviewer");assertEquals("FAILED",view.get("status"));
  @SuppressWarnings("unchecked") var repo=((List<Map<String,Object>>)view.get("repositories")).getFirst();assertEquals("ACCESS_REVOKED",repo.get("error"));
  verify(tester,never()).search(any());
  assertThrows(AccessDeniedException.class,()->searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer"));
  doNothing().when(access).require("reviewer","Rule Modify");
  doThrow(new java.io.IOException("too large")).when(api).downloadSource(eq("orders-service"),anyString(),any(),any());
  String skipped=searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer");searches.run(skipped,progress::add);
  @SuppressWarnings("unchecked") var entry=((List<Map<String,Object>>)searches.get(skipped,"reviewer").get("repositories")).getFirst();
  assertEquals("SKIPPED",entry.get("status"));assertEquals("SOURCE_UNAVAILABLE",entry.get("error"));
  for(int i=0;i<3;i++)searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer");
  assertEquals(3,database.jdbc.queryForObject("SELECT COUNT(*) FROM variant_searches WHERE status='QUEUED'",Integer.class));
  // A lost job (crash, lost message) is reaped after two hours without progress and frees its slot.
  database.jdbc.update("UPDATE variant_searches SET updated_at=0 WHERE status='QUEUED'");searches.reapStale();
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM variant_searches WHERE status='QUEUED'",Integer.class));
  assertEquals(3,database.jdbc.queryForObject("SELECT COUNT(*) FROM variant_search_repositories WHERE error_code='TIMED_OUT'",Integer.class));
  for(int i=0;i<3;i++)searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer");
  assertEquals(429,assertThrows(ResponseStatusException.class,()->searches.start(new VariantSearchService.Start(null,42L,null,List.of(7L)),"reviewer")).getStatusCode().value());
 }
}

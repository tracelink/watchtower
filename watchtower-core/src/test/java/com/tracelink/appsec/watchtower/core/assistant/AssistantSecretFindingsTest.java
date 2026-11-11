package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.data.domain.PageImpl;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** Secrets recorded by any engine are found per repository line and per bypass, over real Hibernate rows. */
class AssistantSecretFindingsTest {
 R1Database database;AssistantSecretFindings secrets;RepoScanReportService reports;RepositoryEntity repo;RepoScanEntity scan;
 static RuleDto rule(long id,String name,String module,String cwe){
  var dto=mock(RuleDto.class);var stewardship=new RuleStewardship();stewardship.setCwe(cwe);
  when(dto.getId()).thenReturn(id);when(dto.getName()).thenReturn(name);when(dto.getModule()).thenReturn(module);when(dto.getStewardship()).thenReturn(stewardship);return dto;
 }
 void violation(long id,Long ruleId,String module,String name,String path,int line){
  database.jdbc.update("INSERT INTO pull_request_violations(vio_entity_id,scan_entity_id,execution_rule_id,rule_module,violation_name,file_path,line_number) VALUES (?,1,?,?,?,?,?)",id,ruleId,module,name,path,line);
 }
 @BeforeEach void setup(){
  database=new R1Database();
  var rules=mock(RuleService.class);
  var known=List.of(rule(1,"generic-api-key","Betterleaks",null),rule(2,"hard-coded-token","Regex"," cwe-798 "),rule(3,"sql-injection","PMD","CWE-89"));
  when(rules.getRules()).thenReturn(known);
  var registry=mock(ScanRegistrationService.class);when(registry.getScannerNames()).thenReturn(List.of("Betterleaks","Regex","PMD"));when(registry.isSensitiveModule("Betterleaks")).thenReturn(true);
  var repoScans=mock(RepoScanRepository.class);reports=mock(RepoScanReportService.class);scan=mock(RepoScanEntity.class);when(scan.getReportKey()).thenReturn("reports/7");
  when(repoScans.findByRepositoryIdOrderBySubmitDateDesc(eq(7L),any())).thenReturn(new PageImpl<>(List.of(scan)));
  when(reports.getReport(scan)).thenReturn(Optional.of(new RepoScanReport(RepoScanReport.SCHEMA,9,"Bitbucket","payments-api","main","c".repeat(40),"default",
    List.of(new RepoScanReport.Finding("unknown-rule","HIGH","config/app.yml",4,"Secret","f1",false,true),new RepoScanReport.Finding("sql-injection","HIGH","src/Query.java",9,"SQL","f2",false,false)),
    List.of(),List.of(),2,null)));
  secrets=database.service(new AssistantSecretFindings(rules,registry,database.records,repoScans,reports));
  repo=mock(RepositoryEntity.class);when(repo.getId()).thenReturn(7L);when(repo.getApiLabel()).thenReturn("bitbucket");when(repo.getRepoName()).thenReturn("payments-api");
  // The pull request webhook stored the display name; the catalog stores the slug.
  database.seedPr(1,System.currentTimeMillis());database.jdbc.update("UPDATE pull_request_container SET api_label='Bitbucket',repo_name='Payments API' WHERE container_id=1");
  violation(1,null,"Betterleaks",null,"src/Config.java",12);
  violation(2,2L,"Regex","hard-coded-token","src/Client.java",30);
  violation(3,3L,"PMD","sql-injection","src/Client.java",40);
  violation(4,null,null,"generic-api-key","src/Client.java",50);
  violation(5,1L,"Betterleaks","generic-api-key","./src//Keys.java",7);
 }
 @AfterEach void close(){database.close();}

 @Test void secretRulesCoverSensitiveScannersAndCredentialCwesFromAnyEngine(){
  var secret=secrets.secretRules();
  assertEquals(Set.of(1L,2L),secret.ids(),"Betterleaks rules and a Regex rule tagged CWE-798 detect secrets; a PMD SQL rule does not");
  assertEquals(Set.of("betterleaks"),secret.modules());
  assertTrue(secret.contains(null,"BETTERLEAKS",null));assertTrue(secret.contains(null,null,"hard-coded-token"));assertFalse(secret.contains(3L,"PMD","sql-injection"));
 }
 @Test void aRuleWhoseNameSaysItDetectsCredentialsIsASecretRuleEvenWithoutACredentialCwe(){
  for(String name:List.of("Slack Token","test (slackwebhook)","RSA private key","aws-access-key-id","DefaultPassword","no-secrets","Bearer header"))
   assertTrue(secrets.isSecretRule(rule(9,name,"Regex",null)),name+" reads as a credential detector");
  for(String name:List.of("sql-injection","ImmutableField","CommentRequired","Tenant isolation best practices"))
   assertFalse(secrets.isSecretRule(rule(9,name,"Regex",null)),name+" is an ordinary rule");
  assertFalse(secrets.isSecretRule(rule(9,null,"Regex",null)),"a rule with no name is judged by its scanner and CWE alone");
 }
 @Test void recordedSecretLinesAreMaskedOnEveryCommitWhateverEngineRecordedThem(){
  var lines=secrets.lines(repo);
  assertEquals("Betterleaks",lines.engine("src/Config.java",12));
  assertEquals("Regex",lines.engine("src/Client.java",30),"another engine's credential rule counts as a secret");
  assertNull(lines.engine("src/Client.java",40),"non-secret findings are not masked");
  assertNotNull(lines.engine("src/Client.java",50),"legacy findings without a rule id are matched by rule name");
  assertNotNull(lines.engine("config/app.yml",4),"repository-scan findings flagged sensitive are masked");
  assertNull(lines.engine("src/Query.java",9));
  assertNull(lines.engine("src/Config.java",13));
  assertEquals("Betterleaks",lines.engine("src/Keys.java",7),"stored and requested spellings are normalized alike");
  assertEquals("Betterleaks",lines.engine("src/./Keys.java",7));
 }
 @Test void aSingleLineIsCheckedWithoutLoadingEveryRecordedSecretLine(){
  var names=List.of("Payments API","payments-api");
  assertTrue(secrets.isRecordedSecretLine(repo,"src/Config.java",12,names),"a pull request secret on exactly this line");
  assertTrue(secrets.isRecordedSecretLine(repo,"src/Client.java",30,names),"another engine's credential rule counts");
  assertTrue(secrets.isRecordedSecretLine(repo,"src/./Keys.java",7,names),"stored and requested spellings are normalized alike");
  assertTrue(secrets.isRecordedSecretLine(repo,"config/app.yml",4,names),"a repository-scan finding flagged sensitive");
  assertFalse(secrets.isRecordedSecretLine(repo,"src/Client.java",40,names),"a non-secret finding does not make its line secret");
  assertFalse(secrets.isRecordedSecretLine(repo,"src/Config.java",13,names),"only the recorded line");
  assertFalse(secrets.isRecordedSecretLine(repo,"src/Query.java",9,names));
  assertFalse(secrets.isRecordedSecretLine(repo,"src/Config.java",12,List.of("Someone Else")),"pull request rows of another repository are not this repository's");
  assertThrows(AssistantSecretFindings.Unavailable.class,()->secrets.isRecordedSecretLine(repo,"",12,names));
  assertThrows(AssistantSecretFindings.Unavailable.class,()->secrets.isRecordedSecretLine(null,"src/A.java",1,names));
  when(reports.getReport(scan)).thenReturn(Optional.empty());
  assertThrows(AssistantSecretFindings.Unavailable.class,()->secrets.isRecordedSecretLine(repo,"src/Config.java",12,names),"an unreadable report fails closed");
 }
 @Test void anUnreadableRepositoryScanReportWithholdsInsteadOfGuessing(){
  when(reports.getReport(scan)).thenReturn(Optional.empty());
  assertThrows(AssistantSecretFindings.Unavailable.class,()->secrets.lines(repo));
 }
 @Test void bypassReasonsAreWithheldWhenAnyCoveredFindingDetectsSecrets(){
  for(long id:List.of(500L,501L,502L))
   database.jdbc.update("INSERT INTO pull_request_bypasses(bypass_id,api_label,repo_name,pr_id,scan_id,bypassed_by,reason,created_at,reason_code) VALUES (?,?,?,?,?,?,?,?,?)",id,"Bitbucket","Payments API","42",1,"dev","reason",1,"OTHER");
  database.jdbc.update("INSERT INTO bypass_finding_identity(bypass_id,finding_id,rule_id,revision) VALUES (500,2,2,NULL)");
  database.jdbc.update("INSERT INTO bypass_finding_identity(bypass_id,finding_id,rule_id,revision) VALUES (501,4,NULL,NULL)");
  database.jdbc.update("INSERT INTO bypass_finding_identity(bypass_id,finding_id,rule_id,revision) VALUES (502,3,3,NULL)");
  assertEquals(Set.of(500L,501L),secrets.bypassesCoveringSecrets(List.of(500L,501L,502L),secrets.secretRules()));
  assertEquals(Set.of(),secrets.bypassesCoveringSecrets(List.of(),secrets.secretRules()));
 }
}

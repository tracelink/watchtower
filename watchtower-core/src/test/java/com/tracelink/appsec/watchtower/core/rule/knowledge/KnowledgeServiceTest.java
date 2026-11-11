package com.tracelink.appsec.watchtower.core.rule.knowledge;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** R5.5 over real Hibernate rows: validation, second-person approval, versions, scope and staleness. */
class KnowledgeServiceTest {
 R1Database database;KnowledgeService knowledge;final AtomicReference<Instant> now=new AtomicReference<>(Instant.parse("2026-10-13T09:00:00Z"));
 String accepted,open;

 @BeforeEach void setup()throws Exception{
  database=new R1Database();
  var repositories=mock(RepositoryRepository.class);when(repositories.existsById(anyLong())).thenAnswer(i->Set.of(42L,43L).contains(i.<Long>getArgument(0)));
  var rules=mock(RuleService.class);when(rules.getRule(anyLong())).thenAnswer(i->{if(Set.of(7L,8L).contains(i.<Long>getArgument(0)))return mock(RuleEntity.class);throw new com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException("missing");});
  Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  knowledge=database.service(new KnowledgeService(database.repository(KnowledgeRepository.class),database.repository(KnowledgeAuditRepository.class),database.records,repositories,rules,clock));
  accepted=UUID.randomUUID().toString();open=UUID.randomUUID().toString();
  for(String[] r:new String[][]{{accepted,"ACCEPTED"},{open,"OPEN"}})
   database.jdbc.update("INSERT INTO rule_review_items(review_id,rule_id,revision,owner,status,reason,recommendation,outcome,created_at,updated_at,version) VALUES (?,7,?,?,?,?,?,?,0,0,1)",r[0],"a".repeat(64),"team",r[1],"noise","Treat Encode.forHtml as a sanitizer","agreed");
 }
 @AfterEach void close(){database.close();}
 KnowledgeService.Proposal proposal(String statement,String language,boolean all,List<Long> repos,List<Long> ruleIds,List<String> cwes,String evidenceId,String reviewBy){
  return new KnowledgeService.Proposal("sanitizer",statement,language,"OWASP Java Encoder","1.2.x",all,repos,ruleIds,cwes,List.of(new KnowledgeService.Evidence("review",evidenceId)),reviewBy);
 }
 KnowledgeService.Proposal valid(){return proposal("org.owasp.encoder.Encode.forHtml escapes HTML output","Java",true,List.of(),List.of(),List.of("cwe-79"),accepted,null);}
 long version(String id){return database.jdbc.queryForObject("SELECT version FROM assistant_knowledge WHERE knowledge_id=?",Long.class,id);}
 @SuppressWarnings("unchecked") List<String> ids(List<Map<String,Object>> rows){return rows.stream().map(r->(String)r.get("id")).toList();}

 @Test void proposalsAreValidatedForScopeEvidenceAndSecretFreeProse(){
  var id=knowledge.propose(valid(),"alice");
  var row=database.jdbc.queryForMap("SELECT kind,language,cwes,review_by,status FROM assistant_knowledge WHERE knowledge_id=?",id);
  assertEquals("SANITIZER",row.get("kind"));assertEquals("java",row.get("language"));assertEquals("[\"CWE-79\"]",row.get("cwes"));
  assertEquals("2027-10-13",row.get("review_by"),"default review date is 12 months out");assertEquals("PROPOSED",row.get("status"));
  for(var bad:List.of(
    proposal("Encode.forHtml escapes HTML output","java",true,List.of(42L),List.of(),List.of(),accepted,null),
    proposal("Encode.forHtml escapes HTML output","java",false,List.of(),List.of(),List.of(),accepted,null),
    proposal("Encode.forHtml escapes HTML output","java",false,List.of(99L),List.of(),List.of(),accepted,null),
    proposal("Encode.forHtml escapes HTML output","java",true,List.of(),List.of(999L),List.of(),accepted,null),
    proposal("Encode.forHtml escapes HTML output","java",true,List.of(),List.of(),List.of("XSS"),accepted,null),
    proposal("Encode.forHtml escapes HTML output","java",true,List.of(),List.of(),List.of(),open,null),
    proposal("Encode.forHtml escapes HTML output","java",true,List.of(),List.of(),List.of(),accepted,"2029-01-01"),
    proposal("Use <script>alert(1)</script> to test","java",true,List.of(),List.of(),List.of(),accepted,null),
    proposal("The test key AKIAABCDEFGHIJKLMNOP is fake","java",true,List.of(),List.of(),List.of(),accepted,null),
    proposal("Token x9f2aQ7hLm3Zp0Vb8Nc4Rt is a dummy","java",true,List.of(),List.of(),List.of(),accepted,null),
    proposal("short","java",true,List.of(),List.of(),List.of(),accepted,null),
    proposal("Encode.forHtml escapes HTML output","",true,List.of(),List.of(),List.of(),accepted,null)))
   assertThrows(IllegalArgumentException.class,()->knowledge.propose(bad,"alice"),bad.toString());
  assertThrows(IllegalArgumentException.class,()->knowledge.propose(new KnowledgeService.Proposal("ignore_rule","Encode.forHtml escapes HTML output","java","x","1",true,List.of(),List.of(),List.of(),List.of(new KnowledgeService.Evidence("review",accepted)),null),"alice"));
 }
 @Test void everyFreeTextFieldIsScreenedForSecretValuesWithoutRejectingOrdinaryNames(){
  for(String secret:List.of("x9f2aQ7hLm3Zp0Vb8Nc4Rt","wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U","AKIAABCDEFGHIJKLMNOP"))
   assertFalse(KnowledgeService.secretFree("value "+secret+" here"),secret);
  for(String ordinary:List.of("Fixed in CVE-2021-44228 by log4j2 2.17","org.owasp.encoder:encoder escapes output","sha256sum and utf8mb4 are fine","Encode.forHtml(value) escapes HTML"))
   assertTrue(KnowledgeService.secretFree(ordinary),ordinary);
  var leakyLibrary=new KnowledgeService.Proposal("sanitizer","Encode.forHtml escapes HTML output","java","lib x9f2aQ7hLm3Zp0Vb8Nc4Rt","1.2.x",true,List.of(),List.of(),List.of(),List.of(new KnowledgeService.Evidence("review",accepted)),null);
  assertThrows(IllegalArgumentException.class,()->knowledge.propose(leakyLibrary,"alice"),"the library field reaches the AI too");
  var wordyVersion=new KnowledgeService.Proposal("sanitizer","Encode.forHtml escapes HTML output","java","OWASP Java Encoder","latest secret",true,List.of(),List.of(),List.of(),List.of(new KnowledgeService.Evidence("review",accepted)),null);
  assertThrows(IllegalArgumentException.class,()->knowledge.propose(wordyVersion,"alice"),"version ranges are version grammar only");
  var nullCwe=new KnowledgeService.Proposal("sanitizer","Encode.forHtml escapes HTML output","java","OWASP Java Encoder","1.2.x",true,List.of(),List.of(),Arrays.asList("CWE-79",null),List.of(new KnowledgeService.Evidence("review",accepted)),null);
  assertThrows(IllegalArgumentException.class,()->knowledge.propose(nullCwe,"alice"));
  var otherRule=new KnowledgeService.Proposal("sanitizer","Encode.forHtml escapes HTML output","java","OWASP Java Encoder","1.2.x",true,List.of(),List.of(8L),List.of(),List.of(new KnowledgeService.Evidence("review",accepted)),null);
  assertThrows(IllegalArgumentException.class,()->knowledge.propose(otherRule,"alice"),"evidence must belong to the scoped rules");
  var id=knowledge.propose(valid(),"alice");
  assertThrows(IllegalArgumentException.class,()->knowledge.reject(id,version(id),"key x9f2aQ7hLm3Zp0Vb8Nc4Rt leaked","bob"),"decision notes are screened too");
 }
 @Test void aDraftIsCheckedLikeARealProposalButMayLeaveLanguageLibraryAndVersionsEmpty(){
  var ok=KnowledgeService.checkedDraft(" sanitizer ","Encode.forHtml escapes HTML output"," Java ","OWASP Java Encoder","1.2.x");
  assertEquals(Map.of("kind","SANITIZER","statement","Encode.forHtml escapes HTML output","language","java","library","OWASP Java Encoder","version_range","1.2.x"),ok);
  var bare=KnowledgeService.checkedDraft("note","Encode.forHtml escapes HTML output",null,null,null);
  assertEquals("",bare.get("language"));assertEquals("",bare.get("library"));assertEquals("",bare.get("version_range"));
  for(Runnable bad:List.<Runnable>of(
    ()->KnowledgeService.checkedDraft("ignore_rule","Encode.forHtml escapes HTML output","java","",""),
    ()->KnowledgeService.checkedDraft("note","too short","java","",""),
    ()->KnowledgeService.checkedDraft("note","Use <b>this</b> encoder for all HTML output","java","",""),
    ()->KnowledgeService.checkedDraft("note","Encode.forHtml escapes HTML output","not a language!","",""),
    ()->KnowledgeService.checkedDraft("note","Encode.forHtml escapes HTML output","java","lib x9f2aQ7hLm3Zp0Vb8Nc4Rt",""),
    ()->KnowledgeService.checkedDraft("note","Encode.forHtml escapes HTML output","java","","latest secret")))
   assertThrows(IllegalArgumentException.class,bad::run);
 }
 @Test void aSecondPersonApprovesAndStaleVersionsAndRepeatDecisionsConflict(){
  var id=knowledge.propose(valid(),"alice");long v=version(id);
  assertEquals(false,knowledge.list("PROPOSED",0,"alice").getFirst().get("can_approve"));
  assertEquals(true,knowledge.list("PROPOSED",0,"bob").getFirst().get("can_approve"));
  assertEquals(403,assertThrows(ResponseStatusException.class,()->knowledge.approve(id,v,"ALICE")).getStatusCode().value(),"the proposer cannot approve, whatever the case");
  assertEquals(409,assertThrows(ResponseStatusException.class,()->knowledge.approve(id,v+1,"bob")).getStatusCode().value());
  knowledge.approve(id,v,"bob");
  assertEquals(409,assertThrows(ResponseStatusException.class,()->knowledge.approve(id,version(id),"carol")).getStatusCode().value());
  assertThrows(IllegalArgumentException.class,()->knowledge.retire(id,version(id),"  ","carol"),"retiring needs a reason");
  knowledge.retire(id,version(id),"Library upgraded to 2.x","carol");
  assertEquals(List.of("PROPOSED","APPROVED","RETIRED"),knowledge.audit(id).stream().map(a->(String)a.get("action")).toList());
  var rejected=knowledge.propose(valid(),"alice");knowledge.reject(rejected,version(rejected),null,"bob");
  assertEquals(List.of(rejected),ids(knowledge.list("REJECTED",0,"bob")));
  assertThrows(IllegalArgumentException.class,()->knowledge.list("DELETED",0,"bob"));
 }
 @Test void chatReceivesOnlyApprovedCurrentEntriesInsideTheirScope(){
  String all=approved(valid());
  String repoScoped=approved(proposal("Encode.forJavaScript escapes script contexts","java",false,List.of(42L),List.of(7L),List.of(),accepted,null));
  String python=approved(proposal("markupsafe.escape escapes HTML output","python",true,List.of(),List.of(),List.of(),accepted,null));
  String shortLived=approved(proposal("Encode.forUri escapes URI components","java",true,List.of(),List.of(),List.of(),accepted,"2026-11-01"));
  knowledge.propose(proposal("Proposed entries are never given to chat","java",true,List.of(),List.of(),List.of(),accepted,null),"alice");
  assertEquals(Set.of(all,shortLived),Set.copyOf(ids(knowledge.applicable(7L,"cwe-79",null,"Java"))),"repository-scoped entries need that repository");
  assertEquals(Set.of(all,repoScoped,shortLived),Set.copyOf(ids(knowledge.applicable(7L,"CWE-79",42L,"java"))));
  assertEquals(Set.of(shortLived),Set.copyOf(ids(knowledge.applicable(8L,"CWE-89",42L,"java"))),"rule and CWE filters narrow entries");
  assertEquals(List.of(python),ids(knowledge.applicable(7L,null,null,"python")));
  assertFalse(knowledge.applicable(7L,null,null,"python").getFirst().containsKey("proposed_by"),"the assistant does not receive people's names");
  assertThrows(IllegalArgumentException.class,()->knowledge.applicable(7L,null,null," "));
  now.set(Instant.parse("2026-11-02T00:00:00Z"));
  assertFalse(ids(knowledge.applicable(7L,"CWE-79",42L,"java")).contains(shortLived),"past its review date, an entry is no longer used");
  assertTrue(knowledge.list("APPROVED",0,"bob").stream().anyMatch(r->shortLived.equals(r.get("id"))&&Boolean.TRUE.equals(r.get("stale"))));
  knowledge.retire(all,version(all),"Superseded","bob");
  assertFalse(ids(knowledge.applicable(7L,"CWE-79",42L,"java")).contains(all));
 }
 String approved(KnowledgeService.Proposal p){var id=knowledge.propose(p,"alice");knowledge.approve(id,version(id),"bob");return id;}
}

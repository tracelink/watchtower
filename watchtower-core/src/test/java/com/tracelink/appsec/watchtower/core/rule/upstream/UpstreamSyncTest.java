package com.tracelink.appsec.watchtower.core.rule.upstream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateService;

/** R5.4: baseline first, then held additions, recorded changes/removals, background check, approval. */
class UpstreamSyncTest {
 R1Database database;UpstreamSyncService sync;RuleService rules=mock(RuleService.class);RuleCandidateService candidates=mock(RuleCandidateService.class);
 AsyncJobService jobs=mock(AsyncJobService.class);List<RuleDto> catalog=new ArrayList<>();ObjectProvider<AsyncJobService> provider;
 RuleDto provided(long id,String name,String revision){
  var dto=mock(RuleDto.class);when(dto.getId()).thenReturn(id);when(dto.getName()).thenReturn(name);when(dto.getModule()).thenReturn("Betterleaks");
  when(dto.isProvided()).thenReturn(true);when(dto.isRetired()).thenReturn(false);when(dto.getRevision()).thenReturn(revision);return dto;
 }
 @BeforeEach void setup(){
  database=new R1Database();
  @SuppressWarnings("unchecked") ObjectProvider<AsyncJobService> mocked=mock(ObjectProvider.class);provider=mocked;when(provider.getObject()).thenReturn(jobs);
  when(jobs.enqueue(any(),anyString(),anyString(),anyString())).thenReturn(Optional.of(new AsyncJobEntity()));
  when(rules.getRules()).thenAnswer(inv->List.copyOf(catalog));
  sync=database.service(new UpstreamSyncService(database.records,rules,candidates,provider,database.tx));
  for(long id=1;id<=4;id++)database.seedRule(id,String.valueOf(id).repeat(64));
 }
 @AfterEach void close(){database.close();}
 Long hold(long id){return database.jdbc.queryForObject("SELECT upstream_hold_since FROM rules WHERE rule_id=?",Long.class,id);}

 @Test void firstSyncIsABaselineAndLaterChangesHoldOnlyNewRules(){
  catalog.addAll(List.of(provided(1,"aws-key","a".repeat(64)),provided(2,"github-pat","b".repeat(64))));
  assertEquals(List.of(),sync.sync(),"existing deployments get a baseline, not a mass hold");
  assertNull(hold(1));assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM upstream_rule_snapshots",Integer.class));
  assertEquals(List.of(),sync.sync(),"no change, no update");

  // Upgrade: one detector removed, one tightened, two added.
  catalog.clear();catalog.addAll(List.of(provided(2,"github-pat","c".repeat(64)),provided(3,"stripe-key","d".repeat(64)),provided(4,"slack-token","e".repeat(64))));
  var created=sync.sync();assertEquals(1,created.size());
  assertNotNull(hold(3));assertNotNull(hold(4));assertNull(hold(2),"changed rules keep blocking; only new rules are held");
  verify(jobs).enqueue(AsyncJobType.UPSTREAM_CHECK,created.getFirst(),"upstream-check:"+created.getFirst(),"system");
  verify(rules).invalidateRuleCache();
  var update=sync.list().getFirst();
  assertEquals("Betterleaks",update.get("module"));assertEquals(2,update.get("held"));assertEquals("QUEUED",update.get("check_status"));
  assertEquals(List.of("slack-token","stripe-key"),((List<?>)update.get("added")).stream().map(a->((Map<?,?>)a).get("name")).toList());
  assertEquals(List.of("github-pat"),((List<?>)update.get("changed")).stream().map(a->((Map<?,?>)a).get("name")).toList());
  assertEquals(List.of("aws-key"),update.get("removed"));
  assertEquals(List.of(),sync.sync(),"the snapshot moved forward, so a second pod records nothing");

  when(candidates.checkCurrent(2)).thenReturn(Map.of("rule_id",2L,"name","github-pat","status","FAILED_EXPECTATION","fixtures",2));
  sync.check(created.getFirst(),note->{});
  assertEquals("FAILED",sync.list().getFirst().get("check_status"),"a reviewed fixture that no longer matches is surfaced");

  long version=((Number)update.get("version")).longValue();
  assertEquals(409,assertThrows(ResponseStatusException.class,()->sync.approve(created.getFirst(),version+1,"steward")).getStatusCode().value());
  sync.approve(created.getFirst(),version,"steward");
  assertNull(hold(3));assertNull(hold(4));assertEquals("steward",sync.list().getFirst().get("approved_by"));
  assertEquals(409,assertThrows(ResponseStatusException.class,()->sync.approve(created.getFirst(),version+1,"steward")).getStatusCode().value());
  assertThrows(IllegalArgumentException.class,()->sync.approve("not-an-id",0,"steward"));
 }
 @Test void readyEventRunsInItsOwnTransactionComparesNamesCaseInsensitivelyAndRecordsEmptiedModules(){
  // The ready listener is invoked on the plain object, not a transactional proxy.
  var raw=new UpstreamSyncService(database.records,rules,candidates,provider,database.tx);
  catalog.add(provided(1,"AWS-Key","a".repeat(64)));raw.onReady();
  catalog.clear();catalog.addAll(List.of(provided(1,"aws-key","a".repeat(64)),provided(2,"Stripe-Key","b".repeat(64))));raw.onReady();
  var update=sync.list().getFirst();
  assertEquals(List.of("Stripe-Key"),((List<?>)update.get("added")).stream().map(a->((Map<?,?>)a).get("name")).toList(),"a case-only rename is the same rule");
  assertEquals(List.of(),update.get("removed"));assertNotNull(hold(2));
  verify(rules).invalidateRuleCache();
  catalog.clear();raw.onReady();
  var emptied=sync.list().getFirst();assertEquals(List.of("Stripe-Key","aws-key"),emptied.get("removed"),"a module that stops providing rules still records removals");
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM upstream_rule_snapshots",Integer.class));
 }
 @Test void checkSummarizesMissingTestsAndUnavailableRuntimesWithoutClaimingAPass(){
  catalog.add(provided(1,"aws-key","a".repeat(64)));sync.sync();
  catalog.clear();catalog.addAll(List.of(provided(1,"aws-key","b".repeat(64)),provided(2,"github-pat","x".repeat(64))));sync.sync();
  catalog.clear();catalog.addAll(List.of(provided(1,"aws-key","c".repeat(64)),provided(2,"github-pat","y".repeat(64))));
  String id=sync.sync().getFirst();
  when(candidates.checkCurrent(1)).thenReturn(Map.of("rule_id",1L,"status","NO_FIXTURES"));when(candidates.checkCurrent(2)).thenThrow(new IllegalStateException("runtime"));
  sync.check(id,note->{});
  var update=sync.list().stream().filter(u->id.equals(u.get("id"))).findFirst().orElseThrow();
  assertEquals("INCOMPLETE",update.get("check_status"));
  assertEquals(List.of("NO_FIXTURES","UNAVAILABLE"),((List<?>)update.get("check")).stream().map(c->((Map<?,?>)c).get("status")).toList());
 }
}

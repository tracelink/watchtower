package com.tracelink.appsec.watchtower.core.assistant.actions;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;
import static com.tracelink.appsec.watchtower.core.assistant.actions.RulesetActions.*;

/** Real JPA transactions: reviewed manifests, complete rollback and durable retry receipts. */
class RulesetChangeSetTest {
 R1Database d;RulesetService domain;RulesetChangeSetService actions;AssistantAccess access;AssistantSettingsService settings;long primary,support,repository;
 @BeforeEach void setup()throws Exception {
  d=new R1Database();access=mock(AssistantAccess.class);settings=mock(AssistantSettingsService.class);
  var cfg=(com.fasterxml.jackson.databind.node.ObjectNode)AssistantState.mapper().readTree(d.jdbc.queryForObject("SELECT config_json FROM assistant_settings",String.class));cfg.put("rulesetActionsEnabled",true);
  var configuration=AssistantState.mapper().treeToValue(cfg,AssistantSettings.class);when(settings.get()).thenReturn(new AssistantSettingsService.Versioned(1,configuration));when(settings.readiness()).thenReturn(new AssistantSettingsService.Readiness(true,null,"Ready"));
  var rules=mock(RuleService.class);when(rules.getRule(anyLong())).thenAnswer(i->d.records.find(RuleEntity.class,i.getArgument(0)));
  domain=d.service(new RulesetService(d.repository(RulesetRepository.class),rules,d.repository(RepositoryRepository.class)));domain.setConfigurationRecords(d.records);
  primary=domain.createRuleset("Primary","Primary rules",RulesetDesignation.PRIMARY).getId();support=domain.createRuleset("Supporting","Supporting rules",RulesetDesignation.SUPPORTING).getId();
  repository=new TransactionTemplate(d.tx).execute(tx->{var repo=new RepositoryEntity();repo.setRepoName("app/python");repo.setScanType(com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.PULL_REQUEST);repo.setRuleset(d.records.find(RulesetEntity.class,primary));d.records.insert(repo);d.records.flush();return repo.getId();});
  actions=d.service(new RulesetChangeSetService(d.records,access,settings,domain));
 }
 @AfterEach void close(){d.close();}
 Operation op(Type t,String target){return new Operation(t,target,null,null,null,null,null,null,null);}
 Request request(Operation... operations){return new Request(UUID.randomUUID().toString(),List.of(operations));}
 Approval approval(View v){return new Approval(v.version(),v.contentHash(),Map.of());}
 @Test void createAndAssignIsOneApprovedAtomicChangeWithDurableRetryReceipt(){
  var req=request(new Operation(Type.CREATE,"local:python","Python","Python rules",RulesetDesignation.PRIMARY,RulePriority.HIGH,List.of(),List.of(Long.toString(support)),List.of()),new Operation(Type.ASSIGN,"local:python",null,null,null,null,null,null,List.of(repository)));
  var view=actions.prepare(req,"alice",null);assertEquals(2,d.jdbc.queryForObject("SELECT COUNT(*) FROM rulesets",Integer.class));assertEquals(primary,d.jdbc.queryForObject("SELECT ruleset_id FROM repositories",Long.class));
  assertEquals(view.id(),actions.prepare(req,"alice",null).id());assertEquals(1,view.preview().repositories().size());
  assertThrows(ResponseStatusException.class,()->actions.apply(view.id(),new Approval(view.version(),"a".repeat(64),Map.of()),"alice"));
  var applied=actions.apply(view.id(),approval(view),"alice");assertEquals("APPLIED",applied.status());assertNotNull(applied.receipt());assertEquals(3,d.jdbc.queryForObject("SELECT COUNT(*) FROM rulesets",Integer.class));
  var again=actions.apply(view.id(),approval(view),"alice");assertEquals(applied.receipt(),again.receipt());assertEquals(1,d.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_ruleset_receipts",Integer.class));
  assertThrows(ResponseStatusException.class,()->actions.get(view.id(),"bob"));
 }
 @Test void referenceChangesForDeletionAreExplicitAndTypedNamesBindExactApproval()throws Exception {
  domain.setDefaultRuleset(primary);
  assertThrows(IllegalArgumentException.class,()->actions.prepare(request(op(Type.DELETE,""+primary)),"alice",null));
  var view=actions.prepare(request(op(Type.DEFAULT,null),new Operation(Type.ASSIGN,null,null,null,null,null,null,null,List.of(repository)),op(Type.DELETE,""+primary)),"alice",null);
  assertThrows(IllegalArgumentException.class,()->actions.apply(view.id(),approval(view),"alice"));assertNotNull(domain.getRuleset(primary));
  actions.apply(view.id(),new Approval(view.version(),view.contentHash(),Map.of(""+primary,"Primary")),"alice");
  assertNull(domain.getDefaultRuleset());assertNull(d.jdbc.queryForObject("SELECT ruleset_id FROM repositories",Long.class));assertEquals(1,d.jdbc.queryForObject("SELECT COUNT(*) FROM rulesets",Integer.class));
 }
 @Test void staleExpiredCanceledAndRevokedApprovalsNeverMutateConfiguration()throws Exception {
  var view=actions.prepare(request(new Operation(Type.UPDATE,""+primary,"Changed","Changed rules",RulesetDesignation.PRIMARY,null,null,null,null)),"alice",null);
  var dto=domain.getRuleset(primary).toDto();dto.setDescription("Concurrent UI edit");domain.editRuleset(dto);
  var initial=view;assertEquals(409,assertThrows(ResponseStatusException.class,()->actions.apply(initial.id(),approval(initial),"alice")).getStatusCode().value());
  view=actions.refresh(view.id(),"alice");var current=view;
  d.jdbc.update("UPDATE assistant_ruleset_change_sets SET expires_at=0 WHERE id=?",view.id());assertEquals(410,assertThrows(ResponseStatusException.class,()->actions.apply(current.id(),approval(current),"alice")).getStatusCode().value());
  view=actions.refresh(view.id(),"alice");var refreshed=view;
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("alice","Ruleset Modify");assertThrows(org.springframework.security.access.AccessDeniedException.class,()->actions.apply(refreshed.id(),approval(refreshed),"alice"));reset(access);
  actions.cancel(view.id(),"alice");assertThrows(ResponseStatusException.class,()->actions.apply(refreshed.id(),approval(refreshed),"alice"));assertEquals("Primary",domain.getRuleset(primary).getName());
 }
 @Test void effectiveMembershipAndProtectionUseTheServerGraph()throws Exception {
  d.seedRule(1,"a".repeat(64));domain.setRules(support,List.of(1L));domain.setInheritedRulesets(primary,List.of(support));
  var view=actions.prepare(request(new Operation(Type.INHERIT,""+primary,null,null,null,null,null,List.of(),null)),"alice",null);
  assertEquals(List.of(1L),view.preview().rulesets().getFirst().effectiveRemoved());assertEquals(1,view.preview().repositories().size());
  assertThrows(IllegalArgumentException.class,()->actions.prepare(request(new Operation(Type.INHERIT,""+support,null,null,null,null,null,List.of(""+primary),null)),"alice",null));
  var provided=domain.createRuleset("Provided","Upstream",RulesetDesignation.PROVIDED);
  assertThrows(IllegalArgumentException.class,()->actions.prepare(request(new Operation(Type.MEMBERSHIP,""+provided.getId(),null,null,null,null,List.of(1L),null,null)),"alice",null));
  assertThrows(IllegalArgumentException.class,()->domain.setRules(provided.getId(),List.of(1L)));
 }
 @Test void lateFailureRollsBackEarlierOperationsAndLeavesNoReceipt(){
  d.jdbc.execute("ALTER TABLE rulesets ADD CONSTRAINT reject_fixture CHECK (name <> 'Reject')");
  var base=request(new Operation(Type.UPDATE,""+primary,"Renamed","New description",RulesetDesignation.PRIMARY,null,null,null,null),new Operation(Type.CREATE,"local:rejected","Reject","Will fail late",RulesetDesignation.PRIMARY,null,null,null,null));var view=actions.prepare(base,"alice",null);
  assertThrows(RuntimeException.class,()->actions.apply(view.id(),approval(view),"alice"));
  assertEquals("Primary",d.jdbc.queryForObject("SELECT name FROM rulesets WHERE ruleset_id=?",String.class,primary));assertEquals("DRAFT",actions.get(view.id(),"alice").status());assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_ruleset_receipts",Integer.class));
 }
 @Test void actionLimitsAndOldTaskScopesCannotBecomeWrites(){
  assertThrows(IllegalArgumentException.class,()->actions.prepare(new Request(UUID.randomUUID().toString(),Collections.nCopies(21,op(Type.DEFAULT,null))),"alice",null));
  var tools=new AssistantToolRegistry(access,mock(RuleService.class),domain,mock(com.tracelink.appsec.watchtower.core.metrics.RuleHealthService.class),mock(RuleReviewService.class),d.records,mock(AssistantSourceTools.class),mock(AssistantSecretFindings.class));tools.setActions(actions,settings);
  assertThrows(IllegalArgumentException.class,()->tools.invoke("alice","prepare_ruleset_changes","{}",1000,"r5-v1",UUID.randomUUID().toString()));
  assertThrows(IllegalArgumentException.class,()->tools.invoke("alice","get_rule","{}",1000,"improvement-v1",UUID.randomUUID().toString()));
  assertFalse(tools.schemas("alice","r5-v1").toString().contains("prepare_ruleset_changes"));
 }
 @Test void concurrentDefaultApprovalsSerializeAndOnlyOnePreviewRemainsCurrent()throws Exception {
  long other=domain.createRuleset("Other primary","Other rules",RulesetDesignation.PRIMARY).getId();
  var a=actions.prepare(request(op(Type.DEFAULT,""+primary)),"alice",null);var b=actions.prepare(request(op(Type.DEFAULT,""+other)),"bob",null);
  var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
  try{var first=pool.submit(()->{start.await();try{actions.apply(a.id(),approval(a),"alice");return true;}catch(ResponseStatusException stale){assertEquals(409,stale.getStatusCode().value());return false;}});var second=pool.submit(()->{start.await();try{actions.apply(b.id(),approval(b),"bob");return true;}catch(ResponseStatusException stale){assertEquals(409,stale.getStatusCode().value());return false;}});start.countDown();assertNotEquals(first.get(10,TimeUnit.SECONDS),second.get(10,TimeUnit.SECONDS));
   assertEquals(1,d.jdbc.queryForObject("SELECT COUNT(*) FROM rulesets WHERE designation='DEFAULT'",Integer.class));assertEquals(1,d.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_ruleset_receipts",Integer.class));
  }finally{pool.shutdownNow();}
 }
}

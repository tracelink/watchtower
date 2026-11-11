package com.tracelink.appsec.watchtower.core.rule.improvement;

import java.io.IOException;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;

/** Engineer-requested proposal tasks reuse the durable assistant workers and shared budgets. */
@Service
public class RuleImprovementService {
 public record Generate(String idempotencyKey,int days,List<String> evidenceIds,String question,String language) { }
 /** Shown when no finding, saved review or missed case exists for the rule in the chosen window. */
 public static final String NO_EVIDENCE="No reviewed findings yet. Review some of this rule's findings first.";
 public record Save(long version,String baseRevision,Map<String,Object> changes,String rationale,String reviewId) { }
 private final LedgerRepository records;private final RuleImprovementEvidence evidence;private final AssistantPersistence db;
 private final RuleCandidateService candidates;private final AssistantAccess access;private final AssistantSettingsService settings;
 public RuleImprovementService(LedgerRepository records,RuleImprovementEvidence evidence,AssistantPersistence db,RuleCandidateService candidates,AssistantAccess access,AssistantSettingsService settings){this.records=records;this.evidence=evidence;this.db=db;this.candidates=candidates;this.access=access;this.settings=settings;}
 @Transactional(rollbackFor=Exception.class)
 public Map<String,Object> generate(long ruleId,Generate request,String owner)throws IOException {
  evidence.require(owner);db.enabled();String key=AssistantPersistence.uuid(request.idempotencyKey());
  if(request.question()==null||request.question().length()>1000||request.evidenceIds()==null||request.evidenceIds().size()>50)throw new IllegalArgumentException("Select up to 50 evidence items and use a question of at most 1000 characters");
  // Serialize duplicate submissions through the existing shared settings row before any paid task.
  records.lock(AssistantSettingsEntity.class,1);String requestHash=RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(Map.of("ruleId",ruleId,"request",request)));
  var prior=records.list(RuleImprovementProposalEntity.class,"SELECT p FROM RuleImprovementProposalEntity p WHERE p.owner=?1 AND p.requestKey=?2",0,1,owner,key);
  if(!prior.isEmpty()){var old=prior.getFirst();if(!requestHash.equals(old.requestHash))throw conflict("This request key belongs to another proposal");return view(old,owner);}
  var gathered=evidence.gather(ruleId,request.days(),request.language(),owner);
  // A proposal needs people's decisions; never pay for one built from nothing (Improve board).
  if(!RuleImprovementEvidence.hasHumanEvidence(gathered))throw new IllegalArgumentException(NO_EVIDENCE);
  Set<String> selected=new HashSet<>(request.evidenceIds());Set<String> available=new HashSet<>();gathered.references().forEach(r->available.add(r.id()));
  if(!available.containsAll(selected))throw new IllegalArgumentException("Selected evidence is unavailable or outside this request scope; reload");
  var references=gathered.references().stream().filter(r->r.id().startsWith("rule/")||r.id().startsWith("health/")||selected.contains(r.id())).toList();
  var selectedManifest=new RuleImprovementEvidence.Manifest(ruleId,gathered.baseRevision(),gathered.days(),gathered.definitionHash(),gathered.editableFields(),gathered.authoringAvailable(),gathered.authoringReasons(),references,gathered.samples(),gathered.limitations());
  String input=RuleDefinitionHistory.encode(Map.of("evidence",selectedManifest,"engineerQuestion",evidence.safeQuestion(ruleId,request.question())));
  // No transcript/source is copied into the durable manifest: identity, revision and hashes only.
  var entity=new RuleImprovementProposalEntity(UUID.randomUUID().toString(),owner,key,selectedManifest,requestHash);
  Map<String,Object> durableManifest=new LinkedHashMap<>();durableManifest.put("ruleId",ruleId);durableManifest.put("baseRevision",entity.baseRevision);durableManifest.put("definitionHash",entity.definitionHash);durableManifest.put("days",gathered.days());durableManifest.put("authoringAvailable",gathered.authoringAvailable());durableManifest.put("samples",gathered.samples());
  durableManifest.put("references",references.stream().map(r->{Map<String,Object> ref=new LinkedHashMap<>();ref.put("id",r.id());ref.put("revision",r.revision());ref.put("contentHash",r.contentHash());return ref;}).toList());entity.manifestJson=RuleDefinitionHistory.encode(durableManifest);
  records.insert(entity);records.flush();String id=entity.id;
  var turn=db.submitScoped(new AssistantPersistence.Submit(null,key,input,null,null),owner,new AssistantPersistence.TaskScope("RULE_IMPROVEMENT",id));
  entity=records.find(RuleImprovementProposalEntity.class,id);entity.turnId=turn.id();entity.model=turn.model();entity.effort=turn.effort();records.flush();return view(entity,owner);
 }
 public void authorizeTask(AssistantPersistence.Turn turn,AssistantState state){
  if(state.taskKind==null)return;
  if(!"RULE_IMPROVEMENT".equals(state.taskKind)||!"improvement-v1".equals(state.toolVersion)||!"improvement-v1".equals(state.promptVersion))throw new IllegalStateException("RECOVERY_CONFIGURATION");
  evidence.require(turn.owner());var row=owned(state.taskId,turn.owner(),false);
  if(!turn.id().equals(row.turnId))throw new IllegalStateException("RECOVERY_CONFIGURATION");
 }
 /** Durable publication is idempotent across a crash before checkpoint delivery. */
 @Transactional
 public void complete(AssistantPersistence.Turn turn,AssistantState state,String answer){
  if(state.taskKind==null)return;db.check(turn);authorizeTask(turn,state);var row=owned(state.taskId,turn.owner(),true);if(!"QUEUED".equals(row.status))return;
  try {
   var manifest=AssistantState.mapper().readTree(row.manifestJson);var proposal=validate(answer,row,manifest);row.proposalJson=RuleDefinitionHistory.encode(proposal.durable());row.status="READY";
  }catch(IllegalArgumentException|IOException invalid){row.status="INVALID_OUTPUT";}
 }
 @Transactional(readOnly=true)
 public Map<String,Object> get(long ruleId,String id,String owner){evidence.require(owner);var row=owned(id,owner,false);if(row.ruleId!=ruleId)throw new ResponseStatusException(HttpStatus.NOT_FOUND);return view(row,owner);}
 @Transactional
 public Map<String,Object> save(long ruleId,String id,Save save,String owner){
  evidence.require(owner);access.require(owner,"Rule Modify");db.enabled();var row=owned(id,owner,true);
  if(row.ruleId!=ruleId)throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  String accepted=RuleDefinitionHistory.encode(save.changes());
  var prior=records.list(RuleCandidateProvenanceEntity.class,"SELECT p FROM RuleCandidateProvenanceEntity p WHERE p.proposalId=?1",0,1,row.id);
  if(!prior.isEmpty()){if(!accepted.equals(prior.getFirst().acceptedPatchJson))throw conflict("This proposal already has a candidate with a different accepted patch");return Map.of("candidateId",prior.getFirst().candidateId);}
  if(row.version!=save.version()||!Objects.equals(row.baseRevision,save.baseRevision()))throw conflict("Proposal version changed; reload");
  if(!"READY".equals(row.status)||row.proposalJson==null)throw new IllegalArgumentException("A validated proposal is required");
  var proposal=parse(row.proposalJson);if(proposal.outcome()!=RuleImprovementProposal.Outcome.PROPOSED_CHANGE)throw new IllegalArgumentException("This proposal offers advice only; no candidate is available");
  var active=candidates.current(ruleId).toDto();if(!Objects.equals(active.getRevision(),row.baseRevision)||!Objects.equals(RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(active)),row.definitionHash))throw conflict("The active rule changed since this proposal. Compare the revisions and regenerate; this proposal will not be rebased");
  // Candidate service locks the rule and repeats current revision/lifecycle/module validation.
  access.require(owner,"Rule Modify");String candidate;
  try{candidate=candidates.create(new RuleCandidateWorkspace.DraftRequest(ruleId,row.baseRevision,save.changes(),save.rationale(),save.reviewId()),owner);}
  catch(IllegalStateException changedPolicy){throw conflict("The module policy or authoring runtime changed; review availability and regenerate the proposal");}
  records.insert(new RuleCandidateProvenanceEntity(candidate,row,owner,accepted));return Map.of("candidateId",candidate);
 }
 RuleImprovementProposal validate(String answer,RuleImprovementProposalEntity row,JsonNode manifest){
  if(answer==null||answer.length()>65536)throw new IllegalArgumentException("Invalid output size");RuleImprovementProposal p=parse(answer);
  if(p.outcome()==null||p.problem()==null||p.problem().isBlank()||p.problem().length()>2000||p.expectedBenefit()==null||p.expectedBenefit().length()>2000||p.changes()==null||p.citations()==null||p.regressions()==null||p.limitations()==null||p.examples()==null||p.proposedTests()==null)throw new IllegalArgumentException("Incomplete proposal");
  Set<String> references=new HashSet<>();manifest.path("references").forEach(r->references.add(r.path("id").asText()));
  if(p.citations().size()>50||!references.containsAll(p.citations())||p.citations().isEmpty())throw new IllegalArgumentException("Citations must resolve to supplied evidence");
  for(var list:List.of(p.regressions(),p.limitations(),p.examples(),p.proposedTests()))if(list.size()>12||list.stream().anyMatch(s->s==null||s.length()>2000))throw new IllegalArgumentException("Oversized proposal");
  if(!AssistantState.mapper().valueToTree(p).equals(AssistantToolRegistry.redact(AssistantState.mapper().valueToTree(p))))throw new IllegalArgumentException("Remove secrets from the proposal");
  if(p.outcome()==RuleImprovementProposal.Outcome.PROPOSED_CHANGE){
   if(!manifest.path("authoringAvailable").asBoolean())throw new IllegalArgumentException("This rule supports advice only");
   candidates.validate(new RuleCandidateService.Draft(row.ruleId,row.baseRevision,RuleDefinitionHistory.JSON.valueToTree(p.changes()),"AI proposal validation",null));
  }else if(!p.changes().isEmpty())throw new IllegalArgumentException("Advice cannot contain a candidate patch");
  return p;
 }
 private static RuleImprovementProposal parse(String json){try{return AssistantState.mapper().readerFor(RuleImprovementProposal.class).with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readValue(json);}catch(Exception e){throw new IllegalArgumentException("Malformed structured proposal");}}
 private RuleImprovementProposalEntity owned(String id,String owner,boolean lock){var row=lock?records.lock(RuleImprovementProposalEntity.class,AssistantPersistence.uuid(id)):records.find(RuleImprovementProposalEntity.class,AssistantPersistence.uuid(id));if(row==null||!owner.equals(row.owner))throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Proposal unavailable");return row;}
 private Map<String,Object> view(RuleImprovementProposalEntity row,String owner){
  var result=new LinkedHashMap<String,Object>();result.put("id",row.id);result.put("ruleId",row.ruleId);result.put("baseRevision",row.baseRevision);result.put("evidenceHash",row.evidenceHash);result.put("version",row.version);result.put("status",row.status);result.put("turnId",row.turnId);result.put("model",row.model);result.put("effort",row.effort);result.put("promptVersion",row.promptVersion);result.put("requester",row.owner);result.put("createdAt",row.createdAt);result.put("proposal",row.proposalJson==null?null:parse(row.proposalJson));
  var active=candidates.current(row.ruleId).toDto();result.put("currentRevision",active.getRevision());result.put("stale",!Objects.equals(active.getRevision(),row.baseRevision)||!Objects.equals(RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(active)),row.definitionHash));result.put("readiness",settings.readiness());
  try{result.put("evidenceReferences",AssistantState.mapper().convertValue(AssistantState.mapper().readTree(row.manifestJson).path("references"),Object.class));}catch(IOException e){throw new IllegalStateException("Evidence identities unavailable");}
  if(row.turnId!=null){var turn=db.turn(row.turnId);result.put("turnStatus",turn.status());result.put("error",turn.error());}
  return result;
 }
 private static ResponseStatusException conflict(String text){return new ResponseStatusException(HttpStatus.CONFLICT,text);}
}

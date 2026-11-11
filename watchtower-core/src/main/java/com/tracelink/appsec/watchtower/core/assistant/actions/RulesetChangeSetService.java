package com.tracelink.appsec.watchtower.core.assistant.actions;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;
import com.tracelink.appsec.watchtower.core.ruleset.*;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import static com.tracelink.appsec.watchtower.core.assistant.actions.RulesetActions.*;

/** Server-owned impact, exact approval and atomic writes. Drafts never alter configuration. */
@Service
public class RulesetChangeSetService {
 private static final int MAX_SETS=2000,MAX_EDGES=20000,MAX_REPOSITORIES=5000,MAX_RULES=50000;
 private final LedgerRepository records;private final AssistantAccess access;private final AssistantSettingsService settings;
 private final RulesetService domain;
 public RulesetChangeSetService(LedgerRepository records,AssistantAccess access,AssistantSettingsService settings,RulesetService domain){this.records=records;this.access=access;this.settings=settings;this.domain=domain;}
 public void require(String owner,boolean assignments){
  for(String grant:List.of("Assistant Use","Ruleset View","Ruleset Modify"))access.require(owner,grant);
  if(assignments)for(String grant:List.of("Repository Settings View","Repository Settings Modify"))access.require(owner,grant);
  if(!settings.get().settings().rulesetActionsEnabled())throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Ruleset actions are off in Assistant settings");
  var ready=settings.readiness();if(!ready.ready())throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,ready.message());
 }
 private static boolean assignments(Request r){return r.operations().stream().anyMatch(o->o.type()==Type.ASSIGN||o.type()==Type.DELETE);}
 @Transactional
 public View prepare(Request request,String owner,String turnId){
  validate(request);require(owner,assignments(request));records.lockScope("ruleset-configuration");
  String key=AssistantPersistence.uuid(request.idempotencyKey()),json=RuleDefinitionHistory.encode(request);
  var prior=records.list(RulesetChangeSetEntity.class,"SELECT c FROM RulesetChangeSetEntity c WHERE c.owner=?1 AND c.requestKey=?2",0,1,owner,key);
  if(!prior.isEmpty()){
   var old=prior.getFirst();if(!old.requestHash.equals(RuleDefinitionHistory.hash(json)))throw conflict("This request key was used for a different change set");return view(old);
  }
  Preview preview=preview(request,load());require(owner,!preview.repositories().isEmpty()||assignments(request));String previewJson=RuleDefinitionHistory.encode(preview);
  var row=new RulesetChangeSetEntity(UUID.randomUUID().toString(),owner,key,turnId,json,previewJson,RuleDefinitionHistory.hash(previewJson),System.currentTimeMillis());
  records.insert(row);records.flush();return view(row);
 }
 @Transactional(readOnly=true)
 public View get(String id,String owner){var row=owned(id,owner,false);require(owner,assignments(request(row))||!parse(row.previewJson,Preview.class).repositories().isEmpty());return view(row);}
 @Transactional
 public View cancel(String id,String owner){var row=owned(id,owner,true);access.require(owner,"Assistant Use");if("APPLIED".equals(row.status))throw conflict("Applied changes cannot be canceled");row.status="CANCELED";records.flush();return view(row);}
 /** The sole application execution entry point; called by authenticated CSRF-protected HTTP only. */
 @Transactional(rollbackFor=Exception.class)
 public View apply(String id,Approval approval,String owner){
  // Global lock first: the same order as prepare/manual graph writes, then change set, then IDs.
  records.lockScope("ruleset-configuration");var row=owned(id,owner,true);Request request=request(row);require(owner,assignments(request));
  if(approval==null||!Objects.equals(row.contentHash,approval.contentHash()))throw conflict("Approval does not match this preview");
  // A response lost after commit returns the immutable original receipt, with no new mutations.
  if("APPLIED".equals(row.status))return view(row);
  if(!"DRAFT".equals(row.status))throw conflict("This draft is canceled");
  if(row.version!=approval.version())throw conflict("The change set changed; review its current preview");
  if(row.expiresAt<=System.currentTimeMillis())throw new ResponseStatusException(HttpStatus.GONE,"Approval expired; refresh this draft and review again");
  Preview expected=parse(row.previewJson,Preview.class),actual=preview(request,load());require(owner,!actual.repositories().isEmpty()||assignments(request));
  if(!row.contentHash.equals(RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(actual))))throw conflict("Configuration or impact changed. Refresh the preview and approve again");
  for(var op:request.operations())if(op.type()==Type.DELETE){
   var before=expected.rulesets().stream().filter(d->d.id().equals(op.target())).findFirst().orElseThrow().before();
   if(approval.deletionNames()==null||!Objects.equals(before.name(),approval.deletionNames().get(op.target())))throw new IllegalArgumentException("Type the exact name of each ruleset being deleted");
  }
  access.require(owner,"Ruleset Modify"); // recheck database grants immediately before writes
  Map<String,Long> created=new TreeMap<>();
  try {for(var op:request.operations())execute(op,created);}catch(com.tracelink.appsec.watchtower.core.exception.rule.RulesetException|com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException|com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException e){throw new IllegalArgumentException(e.getMessage());}
  records.flush();
  var result=new LinkedHashMap<String,Object>();result.put("changeSetId",row.id);result.put("contentHash",row.contentHash);result.put("createdIds",created);
  var changedSets=new ArrayList<Map<String,Object>>();
  for(var diff:expected.rulesets()){
   Long changedId=resolve(diff.id(),created);var entity=records.find(RulesetEntity.class,changedId);
   changedSets.add(entity==null?Map.of("id",changedId,"deleted",true):Map.of("id",changedId,"version",entity.getConfigurationVersion(),"url","/rulesets/"+changedId));
  }
  result.put("rulesets",changedSets);result.put("repositories",expected.repositories().stream().map(a->{var r=records.find(RepositoryEntity.class,a.after().id());return Map.of("id",r.getId(),"version",r.getConfigurationVersion());}).toList());
  long now=System.currentTimeMillis();result.put("appliedAt",now);result.put("actor",owner);
  records.insert(new RulesetExecutionReceiptEntity(row.id,owner,row.contentHash,RuleDefinitionHistory.encode(result),now));row.status="APPLIED";records.flush();return view(row);
 }
 @Transactional
 public View refresh(String id,String owner){
  records.lockScope("ruleset-configuration");var row=owned(id,owner,true);var r=request(row);require(owner,assignments(r));
  if(!"DRAFT".equals(row.status))throw conflict("Only a pending draft can be refreshed");
  var updated=preview(r,load());require(owner,!updated.repositories().isEmpty()||assignments(r));row.previewJson=RuleDefinitionHistory.encode(updated);row.contentHash=RuleDefinitionHistory.hash(row.previewJson);row.expiresAt=System.currentTimeMillis()+1800000;records.flush();return view(row);
 }
 private RulesetChangeSetEntity owned(String id,String owner,boolean lock){
  var row=lock?records.lock(RulesetChangeSetEntity.class,AssistantPersistence.uuid(id)):records.find(RulesetChangeSetEntity.class,AssistantPersistence.uuid(id));
  if(row==null||!owner.equals(row.owner))throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Change set unavailable");return row;
 }
 private Request request(RulesetChangeSetEntity row){return parse(row.requestJson,Request.class);}
 private View view(RulesetChangeSetEntity row){var receipt=records.find(RulesetExecutionReceiptEntity.class,row.id);return new View(row.id,row.version,row.status,row.contentHash,row.expiresAt,parse(row.previewJson,Preview.class),receipt==null?null:parse(receipt.receiptJson,Object.class));}
 private static <T>T parse(String json,Class<T> type){try{return RuleDefinitionHistory.JSON.readValue(json,type);}catch(Exception e){throw new IllegalStateException("Stored action contract is unavailable",e);}}
 private void execute(Operation o,Map<String,Long> created)throws com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException,com.tracelink.appsec.watchtower.core.exception.rule.RulesetException,com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException {
  Long id=o.type()==Type.CREATE?null:resolve(o.target(),created);
  switch(o.type()){
   case CREATE -> {var set=domain.createRuleset(o.name(),o.description(),o.designation());created.put(o.target(),set.getId());var dto=set.toDto();dto.setBlockingLevel(o.blockingLevel());domain.editRuleset(dto);domain.setRules(set.getId(),o.ruleIds());domain.setInheritedRulesets(set.getId(),o.inherited().stream().map(ref->resolve(ref,created)).toList());}
   case UPDATE -> {var dto=domain.getRuleset(id).toDto();dto.setName(o.name());dto.setDescription(o.description());dto.setDesignation(o.designation());dto.setBlockingLevel(o.blockingLevel());domain.editRuleset(dto);}
   case MEMBERSHIP -> domain.setRules(id,o.ruleIds());
   case INHERIT -> domain.setInheritedRulesets(id,o.inherited().stream().map(ref->resolve(ref,created)).toList());
   case DEFAULT -> domain.setDefaultRuleset(id==null?-1:id);
   case DELETE -> domain.deleteRuleset(id);
   case ASSIGN -> {RulesetEntity set=id==null?null:domain.getRuleset(id);for(long repoId:new TreeSet<>(o.repositoryIds())){var repo=records.lock(RepositoryEntity.class,repoId);repo.setRuleset(set);}}
  }
 }
 private static Long resolve(String ref,Map<String,Long> created){if(ref==null)return null;if(ref.startsWith("local:")){Long id=created.get(ref);if(id==null)throw new IllegalArgumentException("A local reference must follow its create operation");return id;}return Long.valueOf(ref);}
 record Snapshot(SortedMap<String,Ruleset> sets,SortedMap<Long,Repository> repositories,SortedMap<Long,Long> rules,Set<Long> secrets) { }
 /** Scalar projections only, bounded and ordered. Oversized catalogs fail closed for this MVP. */
 Snapshot load(){
  SortedMap<String,Ruleset> sets=new TreeMap<>();
  var rows=records.maps("SELECT r.id AS id,r.configurationVersion AS version,r.name AS name,r.description AS description,r.designation AS designation,r.blockingLevel AS blocking FROM RulesetEntity r ORDER BY r.id",0,MAX_SETS+1);bound(rows,MAX_SETS);
  for(var r:rows){String id=r.get("id").toString();sets.put(id,new Ruleset(id,number(r,"version"),(String)r.get("name"),(String)r.get("description"),(RulesetDesignation)r.get("designation"),(com.tracelink.appsec.watchtower.core.rule.RulePriority)r.get("blocking"),new TreeSet<>(),new TreeSet<>()));}
  rows=records.maps("SELECT r.id AS id,i.id AS inherited FROM RulesetEntity r JOIN r.rulesets i ORDER BY r.id,i.id",0,MAX_EDGES+1);bound(rows,MAX_EDGES);for(var r:rows)sets.get(r.get("id").toString()).inherited().add(r.get("inherited").toString());
  rows=records.maps("SELECT r.id AS id,i.id AS rule FROM RulesetEntity r JOIN r.rules i ORDER BY r.id,i.id",0,MAX_RULES+1);bound(rows,MAX_RULES);for(var r:rows)sets.get(r.get("id").toString()).direct().add(number(r,"rule"));
  SortedMap<Long,Repository> repos=new TreeMap<>();rows=records.maps("SELECT r.id AS id,r.configurationVersion AS version,r.repoName AS name,r.ruleset.id AS ruleset FROM RepositoryEntity r ORDER BY r.id",0,MAX_REPOSITORIES+1);bound(rows,MAX_REPOSITORIES);
  for(var r:rows)repos.put(number(r,"id"),new Repository(number(r,"id"),number(r,"version"),(String)r.get("name"),r.get("ruleset")==null?null:r.get("ruleset").toString()));
  SortedMap<Long,Long> rules=new TreeMap<>();Set<Long> secrets=new TreeSet<>();
  rows=records.maps("SELECT r.id AS id,r.persistenceVersion AS version,r.stewardship.cwe AS cwe,TYPE(r) AS type FROM RuleEntity r ORDER BY r.id",0,MAX_RULES+1);bound(rows,MAX_RULES);
  for(var r:rows){long id=number(r,"id");rules.put(id,number(r,"version"));if(AssistantSecretFindings.SECRET_CWES.contains(Objects.toString(r.get("cwe"),"").toUpperCase(Locale.ROOT))||r.get("type").toString().toLowerCase(Locale.ROOT).contains("betterleaks"))secrets.add(id);}
  return new Snapshot(sets,repos,rules,secrets);
 }
 static Preview preview(Request request,Snapshot before){
  var sets=new TreeMap<String,Ruleset>();before.sets().forEach((id,s)->sets.put(id,new Ruleset(id,s.version(),s.name(),s.description(),s.designation(),s.blockingLevel(),new TreeSet<>(s.direct()),new TreeSet<>(s.inherited()))));
  var repos=new TreeMap<>(before.repositories());
  for(var o:request.operations()){
   if(o.type()==Type.CREATE){if(sets.containsKey(o.target()))throw new IllegalArgumentException("Duplicate local reference");sets.put(o.target(),new Ruleset(o.target(),0,o.name(),o.description(),o.designation(),o.blockingLevel(),new TreeSet<>(o.ruleIds()),new TreeSet<>(o.inherited())));}
   else if(o.type()==Type.DEFAULT){
    if(o.target()!=null){var selected=find(sets,o.target());if(selected.designation()!=RulesetDesignation.PRIMARY&&selected.designation()!=RulesetDesignation.DEFAULT)throw new IllegalArgumentException("Only a primary ruleset may be default");}
    sets.replaceAll((id,s)->new Ruleset(id,s.version(),s.name(),s.description(),id.equals(o.target())?RulesetDesignation.DEFAULT:s.designation()==RulesetDesignation.DEFAULT?RulesetDesignation.PRIMARY:s.designation(),s.blockingLevel(),s.direct(),s.inherited()));
   }else if(o.type()==Type.ASSIGN){
    if(o.target()!=null){var s=find(sets,o.target());if(s.designation()==RulesetDesignation.SUPPORTING)throw new IllegalArgumentException("Supporting rulesets cannot be assigned");}
    for(long id:o.repositoryIds()){var r=repos.get(id);if(r==null)throw new IllegalArgumentException("Unknown repository ID "+id);repos.put(id,new Repository(id,r.version(),r.name(),o.target()));}
   }else{
    var s=find(sets,o.target());if(s.designation()==RulesetDesignation.PROVIDED)throw new IllegalArgumentException("Provided rulesets are protected");
    switch(o.type()){
     case UPDATE -> {if(o.designation()==RulesetDesignation.DEFAULT&&s.designation()!=RulesetDesignation.DEFAULT)throw new IllegalArgumentException("Use an explicit default operation");sets.put(s.id(),new Ruleset(s.id(),s.version(),o.name(),o.description(),o.designation(),o.blockingLevel(),s.direct(),s.inherited()));}
     case MEMBERSHIP -> {s.direct().clear();s.direct().addAll(o.ruleIds());}
     case INHERIT -> {s.inherited().clear();s.inherited().addAll(o.inherited());}
     case DELETE -> {
      if(s.designation()==RulesetDesignation.DEFAULT)throw new IllegalArgumentException("Explicitly replace or clear the default before deleting it");
      if(sets.values().stream().anyMatch(x->x.inherited().contains(s.id())))throw new IllegalArgumentException("Explicitly remove every inheritance reference before deleting "+s.name());
      if(repos.values().stream().anyMatch(r->s.id().equals(r.ruleset())))throw new IllegalArgumentException("Explicitly reassign each repository, or select None, before deleting "+s.name());sets.remove(s.id());
     }
     default -> throw new IllegalArgumentException("Unsupported operation");
    }
   }
   validateGraph(sets,repos,before.rules().keySet());
  }
  List<Difference> diffs=new ArrayList<>();Set<String> ids=new TreeSet<>(before.sets().keySet());ids.addAll(sets.keySet());
  for(String id:ids){var old=before.sets().get(id);var next=sets.get(id);var was=effective(before.sets(),id,new HashSet<>());var now=effective(sets,id,new HashSet<>());
   if(!Objects.equals(old,next)||!was.equals(now)){
    var added=difference(now,was);var removed=difference(was,now);var secret=removed.stream().filter(before.secrets()::contains).toList();
    boolean reduced=old!=null&&old.blockingLevel()!=null&&(next==null||next.blockingLevel()==null||next.blockingLevel().getPriority()<old.blockingLevel().getPriority());
    diffs.add(new Difference(id,old,next,added,removed,secret,reduced));
   }
  }
  Set<String> impacted=new HashSet<>();diffs.forEach(d->impacted.add(d.id()));List<Assignment> assignments=new ArrayList<>();
  for(var old:before.repositories().values()){var next=repos.get(old.id());if(!old.equals(next)||impacted.contains(old.ruleset())||impacted.contains(next.ruleset()))assignments.add(new Assignment(old,next));}
  // Manifest includes versions and dependency fingerprints, including rule definitions and graph.
  String hash=RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(before));List<String> grants=new ArrayList<>(List.of("Assistant Use","Ruleset View","Ruleset Modify"));if(assignments(request)||!assignments.isEmpty())grants.addAll(List.of("Repository Settings View","Repository Settings Modify"));
  return new Preview(request.operations(),diffs,assignments,hash,grants,List.of("Assignments never enable engines. Disabled or missing runtimes remain unavailable.","No tests, promotion or scanner settings are changed.","Approval applies only to this exact resource list and preview."));
 }
 private static void validateGraph(Map<String,Ruleset> sets,Map<Long,Repository> repos,Set<Long> rules){
  Set<String> names=new HashSet<>();int defaults=0;
  for(var s:sets.values()){
   if(!names.add(s.name().toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("Duplicate ruleset name");if(s.designation()==RulesetDesignation.DEFAULT)defaults++;
   if(!rules.containsAll(s.direct()))throw new IllegalArgumentException("Unknown rule ID");
   if(s.designation()==RulesetDesignation.SUPPORTING&&s.blockingLevel()!=null)throw new IllegalArgumentException("Supporting rulesets cannot block");
   for(String child:s.inherited()){var c=find(sets,child);if(s.designation()==RulesetDesignation.SUPPORTING&&(c.designation()==RulesetDesignation.PRIMARY||c.designation()==RulesetDesignation.DEFAULT))throw new IllegalArgumentException("Supporting rulesets cannot inherit primary rulesets");}
   effective(sets,s.id(),new HashSet<>());
  }
  if(defaults>1)throw new IllegalArgumentException("Only one default is allowed");
  for(var r:repos.values())if(r.ruleset()!=null&&find(sets,r.ruleset()).designation()==RulesetDesignation.SUPPORTING)throw new IllegalArgumentException("An assigned ruleset cannot become supporting");
 }
 static SortedSet<Long> effective(Map<String,Ruleset> graph,String id,Set<String> path){
  SortedSet<Long> rules=new TreeSet<>();if(id==null||!graph.containsKey(id))return rules;
  if(path.size()>100||!path.add(id))throw new IllegalArgumentException("Inheritance cycle or excessive depth");var s=graph.get(id);rules.addAll(s.direct());for(String parent:s.inherited())rules.addAll(effective(graph,parent,path));path.remove(id);return rules;
 }
 private static List<Long> difference(Set<Long> a,Set<Long> b){return a.stream().filter(id->!b.contains(id)).sorted().toList();}
 private static Ruleset find(Map<String,Ruleset> sets,String id){var r=sets.get(id);if(r==null)throw new IllegalArgumentException("Unknown ruleset reference "+id);return r;}
 private static void bound(List<?> rows,int max){if(rows.size()>max)throw new IllegalArgumentException("Catalog exceeds the MVP preview limit; use manual configuration until paginated impact is available");}
 private static long number(Map<String,Object> row,String key){return ((Number)row.get(key)).longValue();}
 static void validate(Request r){
  if(r==null||r.operations()==null||r.operations().isEmpty()||r.operations().size()>20)throw new IllegalArgumentException("Use 1–20 operations per change set");AssistantPersistence.uuid(r.idempotencyKey());Set<Long> repos=new HashSet<>();
  if(RuleDefinitionHistory.encode(r).length()>65536)throw new IllegalArgumentException("Change set is too large");
  for(var o:r.operations()){
   if(o==null||o.type()==null)throw new IllegalArgumentException("An operation type is required");
   if(o.target()!=null&&!o.target().matches("[1-9][0-9]{0,17}|local:[a-zA-Z][a-zA-Z0-9_-]{0,31}"))throw new IllegalArgumentException("Use exact IDs or change-set-local references");
   if(o.target()==null&&o.type()!=Type.DEFAULT&&o.type()!=Type.ASSIGN)throw new IllegalArgumentException("A target is required");
   if(o.type()==Type.DELETE&&o.target().startsWith("local:"))throw new IllegalArgumentException("Delete targets must be existing ruleset IDs");
   for(String ref:o.inherited())if(ref==null||!ref.matches("[1-9][0-9]{0,17}|local:[a-zA-Z][a-zA-Z0-9_-]{0,31}"))throw new IllegalArgumentException("Invalid inheritance reference");
   if(o.type()==Type.CREATE&&!o.target().startsWith("local:"))throw new IllegalArgumentException("Create requires a local reference");
   if(o.type()==Type.CREATE||o.type()==Type.UPDATE){
    if(o.name()==null||o.name().isBlank()||o.name().length()>100||o.description()==null||o.description().isBlank()||o.description().length()>255)throw new IllegalArgumentException("Provide a bounded name and description");
    if(o.designation()==null||o.designation()==RulesetDesignation.PROVIDED||(o.type()==Type.CREATE&&o.designation()==RulesetDesignation.DEFAULT))throw new IllegalArgumentException("Use primary or supporting designation");
   }else if(o.name()!=null||o.description()!=null||o.designation()!=null||o.blockingLevel()!=null)throw new IllegalArgumentException("Unexpected metadata for this operation");
   if(o.type()!=Type.CREATE&&o.type()!=Type.MEMBERSHIP&&!o.ruleIds().isEmpty()||o.type()!=Type.CREATE&&o.type()!=Type.INHERIT&&!o.inherited().isEmpty()||o.type()!=Type.ASSIGN&&!o.repositoryIds().isEmpty())throw new IllegalArgumentException("Unexpected operation fields");
   if(o.ruleIds().size()>5000||o.inherited().size()>100||o.repositoryIds().size()>500)throw new IllegalArgumentException("Operation is too large");
   if(o.type()==Type.ASSIGN&&o.repositoryIds().isEmpty())throw new IllegalArgumentException("Select exact repository IDs");
   for(Long id:o.repositoryIds())if(id==null||id<=0)throw new IllegalArgumentException("Invalid repository ID");
   for(Long id:o.ruleIds())if(id==null||id<=0)throw new IllegalArgumentException("Invalid rule ID");repos.addAll(o.repositoryIds());
  }
  if(repos.size()>500)throw new IllegalArgumentException("At most 500 explicit assignments per change set");
 }
 private static ResponseStatusException conflict(String text){return new ResponseStatusException(HttpStatus.CONFLICT,text);}
}

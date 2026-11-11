package com.tracelink.appsec.watchtower.core.assistant;

import java.io.*;
import java.util.*;
import java.time.*;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/** Shared claims, durable accepted turns, immutable checkpoints and fenced publication. */
@Service
public class AssistantPersistence {
 public record Turn(String id,String session,String owner,String status,String model,String effort,
   String settingsJson,String checkpoint,String leaseOwner,long leaseVersion,int attempts,long deadline,
   long tokens,long cost,String error) { }
 public record Submit(String sessionId,String idempotencyKey,String message,String model,String effort,com.tracelink.appsec.watchtower.core.assistant.context.ContextRequest context,String draft) {
  public Submit(String sessionId,String idempotencyKey,String message,String model,String effort,com.tracelink.appsec.watchtower.core.assistant.context.ContextRequest context){this(sessionId,idempotencyKey,message,model,effort,context,null);}
  public Submit(String sessionId,String idempotencyKey,String message,String model,String effort){this(sessionId,idempotencyKey,message,model,effort,null,null);}
 }
 /** Published only after the accepted turn commits; a lost event is recovered by periodic claims. */
 public record Accepted(String turnId) { }
 private final LedgerRepository records;private final TransactionTemplate tx;
 private final AssistantTranscriptStore store;private final AssistantSettingsService settings;private final AssistantAccess access;private final ApplicationEventPublisher events;
 public AssistantPersistence(LedgerRepository records,PlatformTransactionManager tm,AssistantTranscriptStore store,AssistantSettingsService settings,AssistantAccess access,ApplicationEventPublisher events){this.records=records;this.tx=new TransactionTemplate(tm);this.store=store;this.settings=settings;this.access=access;this.events=events;}
 public static String uuid(String id){try{return UUID.fromString(id).toString();}catch(Exception e){throw new IllegalArgumentException("Invalid id");}}
 public static String ownerKey(String owner){return RuleRevision.definition("assistant-user","v1").field("owner",owner).hash();}
 public void enabled(){var r=settings.readiness();if(!r.ready())throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,r.message());}
 public Turn turn(String id){var t=records.find(AssistantTurnEntity.class,uuid(id));if(t==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND);return new Turn(t.turnId,t.sessionId,t.owner,t.status,t.model,t.effort,t.settingsJson,t.checkpointKey,t.leaseOwner,t.leaseVersion,t.attempts,t.deadlineAt,t.tokens,t.costMicros,t.errorCode);}
 public void own(Turn turn,String owner){if(!turn.owner().equals(owner))throw new ResponseStatusException(HttpStatus.NOT_FOUND);session(turn.session(),owner);}
 public Map<String,Object> session(String id,String owner){
  var rows=records.maps("SELECT row FROM AssistantSessionEntity row WHERE sessionId=?1 AND owner=?2",0,2147483647 ,uuid(id),owner);
  if(rows.isEmpty())throw new ResponseStatusException(HttpStatus.NOT_FOUND);var s=rows.getFirst();
  if(((Number)s.get("expires_at")).longValue()<=System.currentTimeMillis()||s.get("transcript_purged_at")!=null)throw new ResponseStatusException(HttpStatus.GONE,"Conversation expired");return s;
 }
 public AssistantState state(Turn turn)throws IOException{var limit=settings.decode(turn.settingsJson()).maxTranscriptBytes();return AssistantState.decode(store.get(turn.checkpoint(),limit),limit);}
 private String artifact(String session,String turn,AssistantState state,int max)throws IOException {
  String key="assistant/conversations/"+session+"/"+turn+"/"+UUID.randomUUID()+".json.gz";
  // Independent durable intent makes even rolled-back publication artifacts reclaimable.
  TransactionTemplate intent=new TransactionTemplate(tx.getTransactionManager());intent.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  intent.executeWithoutResult(s->records.insert(new AssistantArtifactEntity(key,session,System.currentTimeMillis(),null)));
  store.put(key,state.encode(max));return key;
 }
 /** Whether this person already has a turn under this idempotency key, so a retry need not rebuild its page card. */
 public boolean hasTurn(String owner,String idempotencyKey){
  try{return records.scalar(Long.class,"SELECT COUNT(*) FROM AssistantTurnEntity WHERE owner=?1 AND idempotencyKey=?2",owner,uuid(idempotencyKey))>0;}
  catch(IllegalArgumentException e){return false;}
 }
 public Turn submit(Submit request,String owner)throws IOException { return submitScoped(request,owner,null,null,null); }
 /** A turn from a page: the card was already resolved for this person from the page's ids. */
 public Turn submit(Submit request,String owner,com.tracelink.appsec.watchtower.core.assistant.context.ContextCard card)throws IOException { return submitScoped(request,owner,null,card,null); }
 /** A turn that also carries the rule draft the person chose to share; {@code draft} is already checked and redacted. */
 public Turn submit(Submit request,String owner,com.tracelink.appsec.watchtower.core.assistant.context.ContextCard card,String draft)throws IOException { return submitScoped(request,owner,null,card,draft); }
 /** Scope is constructed only by an application workflow, never deserialized from chat input. */
 public record TaskScope(String kind,String id) { }
 public Turn submitScoped(Submit request,String owner,TaskScope scope)throws IOException { return submitScoped(request,owner,scope,null,null); }
 public Turn submitScoped(Submit request,String owner,TaskScope scope,com.tracelink.appsec.watchtower.core.assistant.context.ContextCard card,String draft)throws IOException {
  enabled();access.require(owner,"Assistant Use");String idem=uuid(request.idempotencyKey());
  if(request.message()==null||request.message().isBlank()||request.message().length()>(scope==null?16000:settings.get().settings().maxInputBytes()))throw new IllegalArgumentException("Message or selected evidence exceeds the input limit; narrow the selection");
  String text=AssistantText.redact(request.message());
  RuleRevision definition=RuleRevision.definition("assistant-submit","v1").field("task",scope==null?null:scope.kind()+":"+scope.id()).field("message",request.message()).field("session",request.sessionId()).field("model",request.model()).field("effort",request.effort());
  // Only a request with a page carries the field, so a retry of a turn accepted before this existed still matches.
  if(request.context()!=null)definition=definition.field("context",request.context().canonical());
  if(draft!=null)definition=definition.field("draft",draft);
  String hash=definition.hash();
  try {return tx.execute(status->{
   records.lock(AssistantSettingsEntity.class,1);
   var duplicates=records.maps("SELECT turnId AS turn_id,requestHash AS request_hash FROM AssistantTurnEntity WHERE owner=?1 AND idempotencyKey=?2",0,2147483647 ,owner,idem);
   if(!duplicates.isEmpty()){if(!hash.equals(duplicates.getFirst().get("request_hash")))throw new ResponseStatusException(HttpStatus.CONFLICT,"Idempotency key belongs to another request");Turn old=turn((String)duplicates.getFirst().get("turn_id"));own(old,owner);return old;}
   AssistantSettings config=settings.get().settings();if(!config.enabled())throw new ResponseStatusException(HttpStatus.NOT_FOUND);
   long now=System.currentTimeMillis();String sessionId=request.sessionId()==null?UUID.randomUUID().toString():uuid(request.sessionId());AssistantState snapshot=new AssistantState();String model=request.model(),effort=request.effort();
   Map<String,Object> existing=null;
   if(request.sessionId()!=null){existing=session(sessionId,owner);records.lock(AssistantSessionEntity.class,sessionId);if(model==null)model=(String)existing.get("model");if(effort==null)effort=(String)existing.get("effort");}
   if(model==null)model=config.defaultModel();if(effort==null)effort=config.defaultEffort();config.model(model,effort);
   long queued=records.scalar(Long.class,"SELECT COUNT(*) FROM AssistantTurnEntity WHERE activeUser IS NOT NULL");
   if(queued>=config.queueLimit())throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Assistant queue full; retry in 30 seconds");
   if(records.scalar(Long.class,"SELECT COUNT(*) FROM AssistantTurnEntity WHERE activeUser=?1 OR activeSession=?2" ,ownerKey(owner),sessionId)>0)throw new ResponseStatusException(HttpStatus.CONFLICT,"A turn is already in progress");
   if(existing!=null&&existing.get("latest_key")!=null) {
    try{snapshot=AssistantState.decode(store.get((String)existing.get("latest_key"),config.maxTranscriptBytes()),config.maxTranscriptBytes());}catch(IOException e){throw new StorageFailure();}
   }
   snapshot.model=model;snapshot.effort=effort;snapshot.user(text);if(card!=null&&scope==null)snapshot.useContext(card);if(draft!=null&&scope==null)snapshot.useDraft(draft);
   if(scope!=null){if(!"RULE_IMPROVEMENT".equals(scope.kind())||request.sessionId()!=null)throw new IllegalArgumentException("Unsupported workflow scope");snapshot.taskKind=scope.kind();snapshot.taskId=uuid(scope.id());snapshot.promptVersion="improvement-v1";snapshot.toolVersion="improvement-v1";}
   String turnId=UUID.randomUUID().toString(),key;
   try{key=artifact(sessionId,turnId,snapshot,config.maxTranscriptBytes());}catch(IOException e){throw new StorageFailure();}
   long expiry=now+config.retentionDays()*86400000L;
   if(existing==null){var created=new AssistantSessionEntity(sessionId,owner,now,now,now,expiry,model,effort,1,key,null);created.title=scope==null?title(request.message()):null;records.insert(created);}
   else records.update("UPDATE AssistantSessionEntity SET lastUserMessageAt=?1,lastTurnAt=?2,expiresAt=?3,model=?4,effort=?5,turnCount=turnCount+1,latestKey=?6 WHERE sessionId=?7" ,now,now,expiry,model,effort,key,sessionId);
   records.insert(new AssistantTurnEntity(turnId,sessionId,owner,idem,hash,"QUEUED",model,effort,settings.encode(config),key,null,0L,null,0,now+config.deadlineSeconds()*1000L,now,now,0L,0L,null,ownerKey(owner),sessionId));
   // The accepted turn row is the durable work item; legacy outbox rows are only cleaned up.
   TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){events.publishEvent(new Accepted(turnId));}});
   audit(owner,sessionId,turnId,"SUBMITTED",null,model,effort,0,0);return turn(turnId);
  });}catch(StorageFailure e){throw new IOException("Could not persist accepted input");}
 }
 private static class StorageFailure extends RuntimeException { }
 /** Same predicate as claim: queued, or abandoned by a worker whose heartbeat stopped. */
 public List<String> claimable(int limit){long now=System.currentTimeMillis();return records.maps("SELECT turnId AS turn_id FROM AssistantTurnEntity WHERE activeUser IS NOT NULL AND deadlineAt>?1 AND attempts<3 AND (status='QUEUED' OR heartbeatAt<?2) ORDER BY createdAt",0,limit ,now,now-90000).stream().map(row->(String)row.get("turn_id")).toList();}
 public Optional<Turn> claim(String id,String worker) {
  long now=System.currentTimeMillis();
  return tx.execute(s->{
   int changed=records.update("UPDATE AssistantTurnEntity SET status=CASE WHEN attempts=0 THEN 'RUNNING' ELSE 'RECOVERING' END,leaseOwner=?1,leaseVersion=leaseVersion+1,heartbeatAt=?2,attempts=attempts+1,updatedAt=?3 WHERE turnId=?4 AND activeUser IS NOT NULL AND deadlineAt>?5 AND attempts<3 AND (status='QUEUED' OR heartbeatAt<?6)" ,worker,now,now,uuid(id),now,now-90000);
   if(changed==0)return Optional.empty();Turn t=turn(id);audit(t.owner(),t.session(),t.id(),t.attempts()>1?"RECOVERED":"STARTED",null,t.model(),t.effort(),0,0);return Optional.of(t);
  });
 }
 public boolean heartbeat(Turn t){return records.update("UPDATE AssistantTurnEntity SET heartbeatAt=?1 WHERE turnId=?2 AND leaseOwner=?3 AND leaseVersion=?4 AND activeUser IS NOT NULL" ,System.currentTimeMillis(),t.id(),t.leaseOwner(),t.leaseVersion())==1;}
 public void check(Turn t){
  enabled();access.require(t.owner(),"Assistant Use");session(t.session(),t.owner());
  if(t.deadline()<=System.currentTimeMillis())throw new IllegalStateException("TURN_DEADLINE");
  if(!heartbeat(t))throw new IllegalStateException("LEASE_LOST");
  try{settings.get().settings().model(t.model(),t.effort());}catch(IllegalArgumentException e){throw new IllegalStateException("MODEL_UNAVAILABLE");}
 }
 public void checkpoint(Turn t,AssistantState snapshot,boolean complete)throws IOException {
  try {tx.executeWithoutResult(s->{
   records.lock(AssistantSessionEntity.class,t.session());
   check(t);String key;try{key=artifact(t.session(),t.id(),snapshot,settings.decode(t.settingsJson()).maxTranscriptBytes());}catch(IOException e){throw new StorageFailure();}
   if(records.update("UPDATE AssistantTurnEntity SET checkpointKey=?1,status=?2,activeUser=CASE WHEN ?3=TRUE THEN NULL ELSE activeUser END,activeSession=CASE WHEN ?4=TRUE THEN NULL ELSE activeSession END,updatedAt=?5 WHERE turnId=?6 AND leaseOwner=?7 AND leaseVersion=?8 AND activeUser IS NOT NULL" ,key,complete?"COMPLETED":"RUNNING",complete,complete,System.currentTimeMillis(),t.id(),t.leaseOwner(),t.leaseVersion())!=1)throw new IllegalStateException("LEASE_LOST");
   records.update("UPDATE AssistantSessionEntity SET latestKey=?1,lastTurnAt=?2 WHERE sessionId=?3" ,key,System.currentTimeMillis(),t.session());
   if(complete)audit(t.owner(),t.session(),t.id(),"COMPLETED",null,t.model(),t.effort(),0,0);
  });}catch(StorageFailure e){throw new IOException("Checkpoint persistence failed");}
 }
 public void terminal(Turn t,String status,String error){
  if(records.update("UPDATE AssistantTurnEntity SET status=?1,errorCode=?2,activeUser=NULL,activeSession=NULL,updatedAt=?3 WHERE turnId=?4 AND leaseOwner=?5 AND leaseVersion=?6 AND activeUser IS NOT NULL" ,status,error,System.currentTimeMillis(),t.id(),t.leaseOwner(),t.leaseVersion())==1)
   audit(t.owner(),t.session(),t.id(),status,error,t.model(),t.effort(),0,0);
 }
 public void cancel(String id,String owner){Turn t=turn(id);own(t,owner);records.update("UPDATE AssistantTurnEntity SET status='CANCELED',leaseVersion=leaseVersion+1,activeUser=NULL,activeSession=NULL,updatedAt=?1 WHERE turnId=?2 AND activeUser IS NOT NULL" ,System.currentTimeMillis(),t.id());audit(owner,t.session(),t.id(),"CANCELED",null,t.model(),t.effort(),0,0);}
 public List<Map<String,Object>> history(String owner,int offset){if(offset<0||offset>10000)throw new IllegalArgumentException("Invalid page");return records.maps("SELECT sessionId AS session_id,startedAt AS started_at,lastUserMessageAt AS last_user_message_at,lastTurnAt AS last_turn_at,expiresAt AS expires_at,model AS model,effort AS effort,turnCount AS turn_count,title AS title FROM AssistantSessionEntity WHERE owner=?1 AND expiresAt>?2 AND transcriptPurgedAt IS NULL ORDER BY lastTurnAt DESC,sessionId",offset,20 ,owner,System.currentTimeMillis());}
 public List<Map<String,Object>> conversation(String session,String owner)throws IOException{
  var s=session(session,owner);if(s.get("latest_key")==null)return List.of();
  return messages(AssistantState.decode(store.get((String)s.get("latest_key"),1048576),1048576));
 }
 /** The visible messages of a transcript the caller already decoded, so reopening a chat reads storage once. */
 public static List<Map<String,Object>> messages(AssistantState state){
  return AssistantState.mapper().convertValue(state.messages,new com.fasterxml.jackson.core.type.TypeReference<List<Map<String,Object>>>(){});
 }
 private static final int TITLE_MAX=60;
 /** A short label for the chat list: the first question, tidied. Nothing that looks like a secret is ever kept. */
 static String title(String message){
  if(message==null)return null;
  String text=message.strip().replaceAll("\\s+"," ");
  if(text.isEmpty()||!AssistantText.redact(text).equals(text))return null;
  if(text.length()<=TITLE_MAX)return text;
  int cut=text.lastIndexOf(' ',TITLE_MAX);
  return text.substring(0,cut>TITLE_MAX/2?cut:TITLE_MAX)+"...";
 }
 /**
  * Deletes one of the person's own chats: it leaves their history at once and its stored copies are removed
  * by the same expiry path the daily retention job uses. A chat with an answer in progress must be stopped first.
  */
 public void delete(String id,String owner){
  String sessionId=uuid(id);
  tx.executeWithoutResult(status->{
   var current=session(sessionId,owner);
   records.lock(AssistantSessionEntity.class,sessionId);
   if(records.scalar(Long.class,"SELECT COUNT(*) FROM AssistantTurnEntity WHERE sessionId=?1 AND activeUser IS NOT NULL",sessionId)>0)throw new ResponseStatusException(HttpStatus.CONFLICT,"Stop the current answer before deleting this chat");
   records.update("UPDATE AssistantSessionEntity SET expiresAt=?1 WHERE sessionId=?2 AND owner=?3",System.currentTimeMillis(),sessionId,owner);
   audit(owner,sessionId,null,"CHAT_DELETED",null,(String)current.get("model"),(String)current.get("effort"),0,0);
  });
 }
 public void audit(String actor,String session,String turn,String event,String target,String model,String effort,long tokens,long cost){records.insert(new AssistantAuditEntity(null,actor,session,turn,event,target,model,effort,tokens,cost,AssistantState.PROMPT_VERSION,AssistantState.TOOL_VERSION,System.currentTimeMillis()));}
 public LedgerRepository records(){return records;}
 public TransactionTemplate transaction(){return tx;}
 public AssistantTranscriptStore store(){return store;}
}

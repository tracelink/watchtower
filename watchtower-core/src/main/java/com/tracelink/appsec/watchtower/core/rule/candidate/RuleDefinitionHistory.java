package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/** Append-only observed definitions. No historical definition is inferred from a finding/name. */
@Service
public class RuleDefinitionHistory {
 public static final ObjectMapper JSON = JsonMapper.builder()
   .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
   .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS).build();
 private final LedgerRepository records;
 public RuleDefinitionHistory(LedgerRepository records) { this.records=records; }
 private static final Object OBSERVATIONS=new Object();
 private static class Observations { final List<RuleDto> definitions=new ArrayList<>();boolean draining; }
 /** Entity callbacks capture DTOs only; Hibernate writes happen after flushing has returned. */
 public void observe(RuleDto definition) { pending().definitions.add(definition); }
 /** A loaded rule may become dirty without a repository save call. Flush it before commit callbacks end. */
 public void watch() { if(org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive())pending(); }
 private Observations pending() {
  if(!org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive())throw new IllegalStateException("Rule definitions require a managed transaction");
  var existing=(Observations)org.springframework.transaction.support.TransactionSynchronizationManager.getResource(OBSERVATIONS);
  if(existing!=null)return existing;
  var observations=new Observations();
  org.springframework.transaction.support.TransactionSynchronizationManager.bindResource(OBSERVATIONS,observations);
  org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(new org.springframework.transaction.support.TransactionSynchronization(){
   @Override public void beforeCommit(boolean readOnly){if(!readOnly)drain(observations);}
   @Override public void suspend(){org.springframework.transaction.support.TransactionSynchronizationManager.unbindResource(OBSERVATIONS);}
   @Override public void resume(){org.springframework.transaction.support.TransactionSynchronizationManager.bindResource(OBSERVATIONS,observations);}
   @Override public void afterCompletion(int status){org.springframework.transaction.support.TransactionSynchronizationManager.unbindResourceIfPossible(OBSERVATIONS);}
  });
  return observations;
 }
 private void drain(Observations observations) {
  if(observations.draining)return;observations.draining=true;
  try {
   records.flush();
   var captured=List.copyOf(observations.definitions);observations.definitions.clear();
   captured.forEach(this::record);
  }finally{observations.draining=false;}
 }
 public static String encode(Object value) {
  try { return JSON.writeValueAsString(value); }
  catch(Exception e) { throw new IllegalArgumentException("Cannot encode rule evidence"); }
 }
 public static String hash(String value) {
  try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
  catch(Exception e) { throw new IllegalStateException("SHA-256 unavailable",e); }
 }
 public static String definition(RuleDto rule) {
  var node=JSON.valueToTree(rule);
  for(String field:List.of("properties","messages"))if(node.path(field).isArray())
   node.path(field).forEach(item->{if(item.isObject())((com.fasterxml.jackson.databind.node.ObjectNode)item).remove("id");});
  return encode(node);
 }
 public static String actor() {
  var auth=SecurityContextHolder.getContext().getAuthentication();
  return auth==null?"system":auth.getName();
 }
 @org.springframework.transaction.annotation.Transactional
 public void record(RuleDto rule) {
  if(rule.getId()==null||rule.getId()<=0||rule.getRevision()==null)return;
  String definition=definition(rule),hash=hash(definition);
  // Serialize observers on the logical rule, including baseline observers in separate pods.
  records.lock(com.tracelink.appsec.watchtower.core.rule.RuleEntity.class,rule.getId());
  String id=UUID.nameUUIDFromBytes((rule.getId()+":"+hash).getBytes(StandardCharsets.UTF_8)).toString();
  if(records.find(RuleDefinitionVersionEntity.class,id)==null&&records.listBeforeFlush(RuleDefinitionVersionEntity.class,"SELECT v FROM RuleDefinitionVersionEntity v WHERE v.ruleId=?1 AND v.definitionHash=?2",rule.getId(),hash).isEmpty())
   records.insert(new RuleDefinitionVersionEntity(id,rule.getId(),rule.getRevision(),hash,rule.getModule(),definition,actor(),System.currentTimeMillis()));
 }
 /**
  * Whether the rule's definition was seen to change after the given time. False when nothing can be compared: a rule first
  * observed after the time has only its baseline, which is not an edit.
  */
 @org.springframework.transaction.annotation.Transactional(readOnly=true)
 public boolean changedAfter(long ruleId,long millis) {
  long before=records.scalar(Long.class,"SELECT COUNT(v) FROM RuleDefinitionVersionEntity v WHERE v.ruleId=?1 AND v.createdAt<=?2",ruleId,millis);
  long after=records.scalar(Long.class,"SELECT COUNT(v) FROM RuleDefinitionVersionEntity v WHERE v.ruleId=?1 AND v.createdAt>?2",ruleId,millis);
  return before>0&&after>0;
 }
 @org.springframework.transaction.annotation.Transactional
 public List<Map<String,Object>> list(long ruleId,int offset) {
  var observations=(Observations)org.springframework.transaction.support.TransactionSynchronizationManager.getResource(OBSERVATIONS);
  if(observations!=null)drain(observations);
  if(offset<0||offset>10000)throw new IllegalArgumentException("Invalid page");
  return records.maps("SELECT versionId AS version_id,revision AS revision,definitionHash AS definition_hash,module AS module,actor AS actor,createdAt AS created_at FROM RuleDefinitionVersionEntity WHERE ruleId=?1 ORDER BY createdAt DESC,versionId",offset,20 ,ruleId);
 }
}

package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.Map;

/**
 * What the server knows about the page for one person, small enough to put in front of the model.
 * A blocked card carries no details at all; an unavailable card means the page could not be resolved
 * for this person, and chat carries on without it.
 */
public record ContextCard(String kind,String state,String title,Map<String,Object> facts,Map<String,Object> ids) {
 public static final String OK="OK",BLOCKED="BLOCKED",UNAVAILABLE="UNAVAILABLE";
 /** The only text a blocked finding ever produces. */
 public static final String BLOCKED_TITLE="Blocked: secret finding";
 public ContextCard {facts=withoutNulls(facts);ids=withoutNulls(ids);}
 /** Values a record does not have are left out rather than failing the whole card. */
 private static Map<String,Object> withoutNulls(Map<String,Object> source){
  if(source==null)return Map.of();
  var copy=new java.util.LinkedHashMap<String,Object>();
  source.forEach((key,value)->{if(key!=null&&value!=null)copy.put(key,value);});
  return java.util.Collections.unmodifiableMap(copy);
 }
 public static ContextCard ok(String kind,String title,Map<String,Object> facts,Map<String,Object> ids){return new ContextCard(kind,OK,title,facts,ids);}
 public static ContextCard unavailable(String kind){return new ContextCard(kind==null?"unknown":kind,UNAVAILABLE,"Context unavailable",Map.of(),Map.of());}
 /** Ids stay so the card can be checked again on every turn; nothing else about the finding does. */
 public static ContextCard blocked(String kind,Map<String,Object> ids){return new ContextCard(kind,BLOCKED,BLOCKED_TITLE,Map.of(),ids);}
 @com.fasterxml.jackson.annotation.JsonIgnore public boolean isBlocked(){return BLOCKED.equals(state);}
 @com.fasterxml.jackson.annotation.JsonIgnore public boolean isOk(){return OK.equals(state);}
}

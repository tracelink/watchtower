package com.tracelink.appsec.watchtower.core.assistant.context;

/**
 * What the page tells the server about where the person is: a kind and ids, nothing else. Labels and
 * details are never read from the page; the server rebuilds everything from these ids for this person.
 */
public record ContextRequest(Integer v,String kind,Ids ids) {
 public static final int VERSION=1;
 /** Only the ids a kind needs are set; the rest stay null. */
 public record Ids(String scanType,Long scanId,String findingKey,Long repoId,Long ruleId) { }
 /** A stable text of the request, so the same idempotency key cannot carry two different pages. */
 public String canonical(){
  try{return com.tracelink.appsec.watchtower.core.assistant.AssistantState.mapper().writeValueAsString(this);}
  catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Context request could not be written",e);}
 }
}

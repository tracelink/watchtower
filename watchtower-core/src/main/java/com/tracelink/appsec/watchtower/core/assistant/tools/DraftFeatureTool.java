package com.tracelink.appsec.watchtower.core.assistant.tools;

import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.assistant.AssistantTool;

/**
 * A tool behind one admin switch that stores only its own draft, for a person to review and approve on an existing page.
 * It never applies anything. Like every tool it has a strict schema (every field required, no extras).
 */
abstract class DraftFeatureTool implements AssistantTool {
 private final String name,description;private final AssistantFeature feature;private final Set<String> grants;private final ObjectNode schema;
 DraftFeatureTool(String name,String description,AssistantFeature feature,Set<String> grants,Map<String,String> fields){
  this.name=name;this.description=description;this.feature=feature;this.grants=Set.copyOf(grants);
  schema=AssistantState.mapper().createObjectNode().put("type","object").put("additionalProperties",false);
  var props=schema.putObject("properties");var required=schema.putArray("required");
  new TreeMap<>(fields).forEach((field,type)->{props.putObject(field).put("type",type);required.add(field);});
 }
 @Override public final String name(){return name;}
 @Override public final String description(){return description;}
 @Override public final Effect effect(){return Effect.DRAFT_PREPARATION;}
 @Override public final AssistantFeature feature(){return feature;}
 @Override public final ObjectNode schema(){return schema.deepCopy();}
 @Override public final Set<String> authorities(){return grants;}
 @Override public final Object invoke(JsonNode arguments){throw new UnsupportedOperationException("A draft tool needs its turn");}
 /** A plain refusal or a revoked grant passes through; anything else is reported as "not available". */
 @Override public final Object invokeDraft(String owner,JsonNode arguments,String raw,String turnId){
  try{return draft(owner,arguments,raw,turnId);}
  catch(IllegalArgumentException|org.springframework.security.access.AccessDeniedException e){throw e;}
  // A conflict or a limit is a plain refusal the turn can carry on from, not a failure of the whole turn.
  catch(org.springframework.web.server.ResponseStatusException e){throw new IllegalArgumentException(e.getReason()==null?"Not available":e.getReason());}
  catch(RuntimeException e){throw new IllegalArgumentException("Not available");}
 }
 abstract Object draft(String owner,JsonNode arguments,String raw,String turnId);
}

package com.tracelink.appsec.watchtower.core.assistant.tools;

import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.assistant.AssistantTool;

/** A read-only tool behind one admin switch, with a strict schema (every field required, no extras). */
abstract class FeatureTool implements AssistantTool {
 private final String name,description;private final AssistantFeature feature;private final Set<String> grants;private final ObjectNode schema;
 /** {@code fields} maps each argument name to its JSON type. */
 FeatureTool(String name,AssistantFeature feature,Set<String> grants,Map<String,String> fields){this(name,null,feature,grants,fields);}
 /** As above, with the wording the model is told about the tool (null for the generic wording). */
 FeatureTool(String name,String description,AssistantFeature feature,Set<String> grants,Map<String,String> fields){
  this.name=name;this.description=description;this.feature=feature;this.grants=Set.copyOf(grants);
  schema=AssistantState.mapper().createObjectNode().put("type","object").put("additionalProperties",false);
  var props=schema.putObject("properties");var required=schema.putArray("required");
  new TreeMap<>(fields).forEach((field,type)->{props.putObject(field).put("type",type);required.add(field);});
 }
 @Override public final String name(){return name;}
 @Override public final String description(){return description;}
 @Override public final Effect effect(){return Effect.EVIDENCE_READ;}
 @Override public final AssistantFeature feature(){return feature;}
 @Override public final ObjectNode schema(){return schema.deepCopy();}
 @Override public final Set<String> authorities(){return grants;}
 @Override public final Object invoke(JsonNode arguments){throw new UnsupportedOperationException("This tool acts for a person");}
 /** Anything other than a plain refusal or a revoked grant is reported as "not available", so one bad record cannot fail the whole turn. */
 @Override public final Object invoke(String owner,JsonNode arguments){
  try{return read(owner,arguments);}
  catch(IllegalArgumentException|org.springframework.security.access.AccessDeniedException e){throw e;}
  catch(RuntimeException e){throw new IllegalArgumentException("Not available");}
 }
 abstract Object read(String owner,JsonNode arguments);
}

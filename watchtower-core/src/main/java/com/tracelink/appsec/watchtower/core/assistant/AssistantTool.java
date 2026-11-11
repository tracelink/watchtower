package com.tracelink.appsec.watchtower.core.assistant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Set;

/** Bounded tools have explicit schemas and server-enforced current grants. */
public interface AssistantTool {
 /**
  * What a tool may do. Reads write nothing except audit and the person's own record that they saw an AI opinion. A draft tool writes only its own draft, which a
  * person reviews and approves on an existing page. {@code HUMAN_APPROVED_EXECUTION} names what only a
  * person may do, so no tool may declare it and the registry refuses to register one.
  */
 enum Effect { EVIDENCE_READ, DRAFT_PREPARATION, HUMAN_APPROVED_EXECUTION }
 /** Every tool states its effect; there is no default. */
 Effect effect();
 /** The admin switch that must be on for the tool to be offered or run, or null for the core tools. */
 default AssistantFeature feature(){return null;}
 String name();ObjectNode schema();Set<String> authorities();Object invoke(JsonNode arguments);
 /** Tools that act for the signed-in person (assessment views, for one) receive who is asking. */
 default Object invoke(String owner,JsonNode arguments){return invoke(arguments);}
 /** What the model is told about the tool, or null for the generic wording. */
 default String description(){return null;}
 /**
  * A draft tool stores only its own draft, which a person reviews and approves on an existing page. {@code raw} is the
  * argument text the model sent, so the same call in the same turn is the same draft. A draft tool without a handler is refused.
  */
 default Object invokeDraft(String owner,JsonNode arguments,String raw,String turnId){throw new IllegalArgumentException("Draft tool has no handler");}
}

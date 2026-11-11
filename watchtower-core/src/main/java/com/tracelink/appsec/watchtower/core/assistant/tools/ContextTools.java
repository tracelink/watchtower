package com.tracelink.appsec.watchtower.core.assistant.tools;

import java.util.*;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.AssistantTool;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAssessmentService;
import com.tracelink.appsec.watchtower.core.assistant.context.*;

/**
 * Read-only tools for the page-aware assistant. Each returns what the same person could read on the
 * page, and a finding of a secret rule only ever comes back as {@code {"blocked":"secret finding"}}.
 * None of them records a judgment, decides a bypass or changes anything. The assessment service is
 * looked up when used because it depends on the tool registry that registers these tools.
 */
@Component
public class ContextTools {
 /** The one answer for a secret finding: no path, line, rule or reason. */
 public static final Map<String,Object> BLOCKED=Map.of("blocked","secret finding");
 private static final Set<String> SCAN_GRANT=Set.of("Scan Results View");
 private final FindingContextProvider findings;private final RepositoryContextProvider repositories;private final PullRequestContextProvider pullRequests;
 private final ScanSummaries summaries;private final org.springframework.beans.factory.ObjectProvider<FindingAssessmentService> assessments;
 public ContextTools(FindingContextProvider findings,RepositoryContextProvider repositories,PullRequestContextProvider pullRequests,ScanSummaries summaries,org.springframework.beans.factory.ObjectProvider<FindingAssessmentService> assessments){
  this.findings=findings;this.repositories=repositories;this.pullRequests=pullRequests;this.summaries=summaries;this.assessments=assessments;
 }
 public List<AssistantTool> tools(){
  var findingFields=Map.of("scan_type","string","scan_id","integer","finding_key","string");
  return List.of(
   new FeatureTool("get_finding",AssistantFeature.CONTEXT_CARDS,SCAN_GRANT,findingFields){
    @Override Object read(String owner,JsonNode a){return findingFacts(a);}
   },
   new FeatureTool("get_finding_assessment",AssistantFeature.FINDING_ASSESSMENT,AssistantSourceTools.GRANTS,findingFields){
    @Override Object read(String owner,JsonNode a){
     // A finding that became secret since it was assessed is blocked before the stored answer is read.
     var facts=findingFacts(a);if(facts==BLOCKED)return BLOCKED;
     var stored=new LinkedHashMap<>(assessments.getObject().latest(owner,a.get("scan_type").asText(),a.get("scan_id").asLong(),a.get("finding_key").asText()));
     stored.put("label","AI advice, not a verdict. A person records the judgment.");
     return stored;
    }
   },
   new FeatureTool("get_repository",AssistantFeature.CONTEXT_CARDS,Set.of("Repository Settings View"),Map.of("repo_id","integer")){
    @Override Object read(String owner,JsonNode a){return facts(repositories.resolve(new ContextRequest.Ids(null,null,null,a.get("repo_id").asLong(),null)));}
   },
   new FeatureTool("get_pull_request",AssistantFeature.CONTEXT_CARDS,SCAN_GRANT,Map.of("scan_id","integer")){
    @Override Object read(String owner,JsonNode a){return facts(pullRequests.resolve(new ContextRequest.Ids(null,a.get("scan_id").asLong(),null,null,null)));}
   },
   new FeatureTool("get_scan_summary",AssistantFeature.CONTEXT_CARDS,SCAN_GRANT,Map.of("scan_type","string","scan_id","integer")){
    @Override Object read(String owner,JsonNode a){return summaries.summary(a.get("scan_type").asText(),a.get("scan_id").asLong());}
   });
 }
 private Object findingFacts(JsonNode a){
  return facts(findings.resolve(new ContextRequest.Ids(a.get("scan_type").asText(),a.get("scan_id").asLong(),a.get("finding_key").asText(),null,null)));
 }
 /** A card as tool output: the same facts, a plain refusal when it is unavailable, and only the marker when it is blocked. */
 private static Object facts(ContextCard card){
  if(card.isBlocked())return BLOCKED;
  if(!card.isOk())throw new IllegalArgumentException("Not available");
  var data=new LinkedHashMap<String,Object>(card.facts());data.put("title",card.title());return data;
 }
}

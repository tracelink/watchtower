package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;

/** The card for a pull request report: gate state and counts, never a secret finding's rule or location. */
@Component
public class PullRequestContextProvider implements ContextProvider {
 private final ScanSummaries summaries;
 public PullRequestContextProvider(ScanSummaries summaries){this.summaries=summaries;}
 @Override public String kind(){return "pull_request";}
 @Override public Set<String> grants(){return Set.of("Scan Results View");}
 @Override public ContextCard resolve(ContextRequest.Ids ids){
  if(ids.scanId()==null||ids.scanId()<1)return ContextCard.unavailable(kind());
  Map<String,Object> facts;
  try{facts=new LinkedHashMap<>(summaries.summary("pull_request",ids.scanId()));}
  catch(IllegalArgumentException e){return ContextCard.unavailable(kind());}
  // The per-rule list belongs to the summary tool; the card carries counts only.
  facts.remove("top_rules");
  return ContextCard.ok(kind(),"Pull request · "+facts.get("repository")+" #"+facts.get("pull_request"),facts,ContextService.idMap(new ContextRequest.Ids(null,ids.scanId(),null,null,null)));
 }
}

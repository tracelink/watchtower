package com.tracelink.appsec.watchtower.core.assistant.tools;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.assistant.AssistantTool;
import com.tracelink.appsec.watchtower.core.assistant.SecretLooks;
import com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteActions;
import com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteChangeSetService;
import com.tracelink.appsec.watchtower.core.assistant.digest.HomeDigestService;
import com.tracelink.appsec.watchtower.core.assistant.features.BypassSummaryService;
import com.tracelink.appsec.watchtower.core.assistant.features.FixtureDraftService;
import com.tracelink.appsec.watchtower.core.assistant.features.JobDiagnosisService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * Tools for Home, jobs, alerts, bypass requests and missed cases. Five only read, and each returns what the same person could
 * read on the page; a secret is only ever the marker. One drafts alert-route changes for a person to review and apply
 * on its own page. None records a judgment, decides a bypass or applies a change. The services are looked up when a tool runs,
 * because some of them depend on the tool registry that registers these tools.
 */
@Component
public class OperationsTools {
 /** The one answer for a secret: no path, line, rule or reason. */
 public static final Map<String,Object> BLOCKED=ContextTools.BLOCKED;
 static final int MAX_ROUTES=100;
 private final ObjectProvider<HomeDigestService> home;private final ObjectProvider<JobDiagnosisService> jobs;private final ObjectProvider<BypassSummaryService> bypass;
 private final ObjectProvider<FixtureDraftService> fixtures;private final ObjectProvider<AlertRouteChangeSetService> changes;private final ObjectProvider<LedgerRepository> records;
 public OperationsTools(ObjectProvider<HomeDigestService> home,ObjectProvider<JobDiagnosisService> jobs,ObjectProvider<BypassSummaryService> bypass,
   ObjectProvider<FixtureDraftService> fixtures,ObjectProvider<AlertRouteChangeSetService> changes,ObjectProvider<LedgerRepository> records){
  this.home=home;this.jobs=jobs;this.bypass=bypass;this.fixtures=fixtures;this.changes=changes;this.records=records;
 }

 public List<AssistantTool> tools(){
  return List.of(
   // Each read sits behind the switch of the feature whose data it shows, so turning a feature off also stops chat reading it.
   new FeatureTool("get_home_overview","Counts for the last 7 whole days against the 7 before, integration states and waiting bypass requests. Counts only.",AssistantFeature.HOME_DIGEST,Set.of("Scan Dashboard View"),Map.of()){
    @Override Object read(String owner,JsonNode a){return home.getObject().currentCounts();}
   },
   new FeatureTool("get_job","State, age and cleaned-up text of one background job from the repository scans Queue page. Other jobs are not available.",AssistantFeature.JOB_DIAGNOSIS,Set.of("Scan Results View"),Map.of("job_id","integer")){
    @Override Object read(String owner,JsonNode a){return jobs.getObject().jobFacts(a.get("job_id").asLong());}
   },
   new FeatureTool("get_alert_config","Alert channels (name, on or off; never a webhook address) and every alert route with its version, which prepare_alert_route_changes needs as baseVersion.",AssistantFeature.ALERT_COPILOT,Set.of("Alert Settings View"),Map.of()){
    @Override Object read(String owner,JsonNode a){return alertConfig();}
   },
   new FeatureTool("get_bypass_request","The state, reason and counts of what one bypass request covers. No names; only the marker when it covers a secret finding.",AssistantFeature.BYPASS_SUMMARY,Set.of("Scan Results View","PR Scan Bypass"),Map.of("request_id","integer")){
    @Override Object read(String owner,JsonNode a){return bypass.getObject().facts(owner,a.get("request_id").asLong());}
   },
   new FeatureTool("get_missed_case_evidence","The lines around a recorded missed vulnerability at the vulnerable and the fixed commit, with recorded secret lines masked, so you can write a small synthetic example in the chat. Only the marker when a secret is near.",AssistantFeature.MISSED_CASE,AssistantSourceTools.GRANTS,Map.of("case_id","string")){
    @Override Object read(String owner,JsonNode a){return caseEvidence(owner,a.get("case_id").asText());}
   },
   new DraftFeatureTool("prepare_alert_route_changes",ALERT_DESCRIPTION,AssistantFeature.ALERT_COPILOT,Set.of("Alert Settings View","Alert Settings Modify"),Map.of("operations_json","string")){
    @Override Object draft(String owner,JsonNode a,String raw,String turnId){return prepareAlertChanges(owner,a.get("operations_json").asText(),raw,turnId);}
   });
 }

 static final String ALERT_DESCRIPTION="Drafts alert-route changes for a person to review and apply on the review page; it never applies them and never touches channels. "
  +"operations_json is a JSON array of at most 5 {type,routeId,alertType,channelId,minPriority,apiLabelFilter,repoInclude,repoExclude,aggregation,dedupeWindowHours,baseVersion}. "
  +"type is ADD, UPDATE or REMOVE. ADD has routeId null and baseVersion null. UPDATE and REMOVE need routeId and that route's version from get_alert_config as baseVersion; UPDATE repeats every field of the route with only the asked change. "
  +"minPriority is HIGH, MEDIUM_HIGH, MEDIUM, MEDIUM_LOW, LOW, INFORMATIONAL or null; aggregation is PER_SCAN or PER_FINDING. Use null for no filter. Read get_alert_config first; ask the person if anything is unclear.";

 /** Channels (name, whether on) and every route with the version a draft must name; never a webhook address. */
 private Object alertConfig(){
  var db=records.getObject();var result=new LinkedHashMap<String,Object>();
  var channels=new ArrayList<Map<String,Object>>();
  for(var row:db.maps("SELECT c.id AS id,c.name AS name,c.enabled AS enabled FROM AlertChannelEntity c ORDER BY c.id",0,MAX_ROUTES))channels.add(Map.of("id",row.get("id"),"name",safe(row.get("name")),"enabled",row.get("enabled")));
  result.put("channels",channels);
  var routes=new ArrayList<Map<String,Object>>();
  for(var row:db.maps("SELECT r.id AS id,r.configurationVersion AS version,r.alertType AS alertType,r.channel.id AS channelId,r.enabled AS enabled,r.minPriority AS minPriority,r.aggregation AS aggregation,"
    +"r.dedupeWindowHours AS dedupeWindowHours,r.apiLabelFilter AS apiLabelFilter,r.repoInclude AS repoInclude,r.repoExclude AS repoExclude FROM AlertRouteEntity r ORDER BY r.id",0,MAX_ROUTES)){
   var route=new LinkedHashMap<String,Object>();
   row.forEach((key,value)->{if(value!=null)route.put(key,value instanceof Enum<?> e?e.name():value);});
   routes.add(route);
  }
  result.put("routes",routes);
  // A list cut at the limit says so, so a missing route is not taken for a route that does not exist.
  if(channels.size()>=MAX_ROUTES||routes.size()>=MAX_ROUTES)result.put("truncated",true);
  return result;
 }
 private static String safe(Object name){String text=String.valueOf(name);return SecretLooks.looksLikeSecret(text)?"(withheld)":text;}

 /** The masked lines around a missed case, or only the marker when a secret is near them. */
 private Object caseEvidence(String owner,String caseId){
  var evidence=fixtures.getObject().evidence(owner,caseId);
  String state=String.valueOf(evidence.get("state"));
  if("BLOCKED".equals(state))return BLOCKED;
  if(!"READY".equals(state))throw new IllegalArgumentException("Not available");
  var out=new LinkedHashMap<String,Object>();
  out.put("evidence",evidence.get("facts"));
  out.put("note","Lines are masked where a secret was recorded. They stay in this chat's record until it is deleted and are saved nowhere else; any example you write stays in this chat.");
  return out;
 }

 /** One draft for the whole call: the same arguments in the same turn are the same draft. A person reviews and applies it. */
 private Object prepareAlertChanges(String owner,String operationsJson,String raw,String turnId){
  List<AlertRouteActions.Operation> operations;
  try{operations=AssistantState.mapper().readValue(operationsJson,new TypeReference<List<AlertRouteActions.Operation>>(){});}
  catch(java.io.IOException e){throw new IllegalArgumentException("Invalid operations JSON");}
  if(operations==null||operations.isEmpty())throw new IllegalArgumentException("Give at least one change in operations_json");
  for(var op:operations)
   if(op!=null&&op.type()!=null&&op.type()!=AlertRouteActions.Type.ADD&&op.baseVersion()==null)throw new IllegalArgumentException("Name each route's version (baseVersion) from get_alert_config");
  String key=UUID.nameUUIDFromBytes((turnId+":"+raw).getBytes(StandardCharsets.UTF_8)).toString();
  var view=changes.getObject().prepare(new AlertRouteActions.Request(key,operations),owner,turnId);
  var result=new LinkedHashMap<String,Object>();
  result.put("changeSetId",view.id());result.put("status",view.status());result.put("reviewUrl","/assistant/alert-changes/"+view.id()+"/review");
  result.put("changes",view.preview().changes().size());result.put("expiresAt",view.expiresAt());
  result.put("message","A person must review and approve this on the review page. No routes were changed.");
  return result;
 }
}

package com.tracelink.appsec.watchtower.core.assistant.alerts;

import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.alerting.AlertSettingsService;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSettingsService;
import com.tracelink.appsec.watchtower.core.assistant.AssistantPersistence;
import com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteActions.*;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/**
 * Drafts, previews and applies alert-route changes. A draft never alters a route; applying needs the
 * person's own Alert Settings Modify grant and happens in one transaction, and only when every route it
 * touches is still at the version the draft was made against. Channels and webhook URLs are never touched.
 */
@Service
public class AlertRouteChangeSetService {
 public static final int MAX_OPERATIONS=5;
 static final String LOCK="alert-route-configuration";
 public static final List<String> GRANTS=List.of("Assistant Use","Alert Settings View","Alert Settings Modify");
 public static final String CHANGED="Routes changed since this draft. Refresh the preview, check it, and approve again.";
 private static final Logger LOG=LoggerFactory.getLogger(AlertRouteChangeSetService.class);
 private final LedgerRepository records;private final AlertSettingsService alerts;private final AssistantAccess access;private final AssistantSettingsService settings;
 public AlertRouteChangeSetService(LedgerRepository records,AlertSettingsService alerts,AssistantAccess access,AssistantSettingsService settings){this.records=records;this.alerts=alerts;this.access=access;this.settings=settings;}

 /** Applying or extending a draft needs the feature to be on, as drafting does; reading and canceling stay open. */
 private void requireFeatureOn(){
  var cfg=settings.get().settings();
  if(!cfg.enabled()||!cfg.isFeatureOn(AssistantFeature.ALERT_COPILOT))throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"The alert-route copilot is off in Assistant settings");
 }

 public void require(String owner){for(String grant:GRANTS)access.require(owner,grant);}

 @Transactional
 public View prepare(Request request,String owner,String turnId){
  validateShape(request);require(owner);records.lockScope(LOCK);
  String key=AssistantPersistence.uuid(request.idempotencyKey()),json=RuleDefinitionHistory.encode(request),requestHash=RuleDefinitionHistory.hash(json);
  var prior=records.list(AlertRouteChangeSetEntity.class,"SELECT c FROM AlertRouteChangeSetEntity c WHERE c.owner=?1 AND c.requestKey=?2",0,1,owner,key);
  if(!prior.isEmpty()){
   if(!prior.getFirst().requestHash.equals(requestHash))throw conflict("This request key was used for a different change set");
   return view(prior.getFirst());
  }
  String previewJson=RuleDefinitionHistory.encode(preview(request));
  var row=new AlertRouteChangeSetEntity(UUID.randomUUID().toString(),owner,key,turnId,json,requestHash,previewJson,RuleDefinitionHistory.hash(previewJson),System.currentTimeMillis());
  records.insert(row);records.flush();return view(row);
 }

 @Transactional(readOnly=true)
 public View get(String id,String owner){var row=owned(id,owner,false);require(owner);return view(row);}

 @Transactional
 public View cancel(String id,String owner){
  var row=owned(id,owner,true);require(owner);
  if("APPLIED".equals(row.status))throw conflict("Applied changes cannot be canceled");
  row.status="CANCELED";records.flush();return view(row);
 }

 /** Re-reads the routes, replaces the preview and starts a new 30 minutes. */
 @Transactional
 public View refresh(String id,String owner){
  records.lockScope(LOCK);var row=owned(id,owner,true);require(owner);requireFeatureOn();
  if(!"DRAFT".equals(row.status))throw conflict("Only a pending draft can be refreshed");
  String previewJson;
  try{previewJson=RuleDefinitionHistory.encode(preview(request(row)));}
  catch(IllegalArgumentException e){throw conflict("A route this draft changes was edited or removed. Ask for the change again.");}
  row.previewJson=previewJson;row.contentHash=RuleDefinitionHistory.hash(previewJson);row.expiresAt=System.currentTimeMillis()+AlertRouteChangeSetEntity.LIFETIME_MILLIS;
  records.flush();return view(row);
 }

 /** The only way a draft reaches the routes; called by an authenticated, CSRF-protected request. */
 @Transactional(rollbackFor=Exception.class)
 public View apply(String id,Approval approval,String owner){
  records.lockScope(LOCK);var row=owned(id,owner,true);require(owner);requireFeatureOn();
  if(approval==null||!Objects.equals(row.contentHash,approval.contentHash()))throw conflict("Approval does not match this preview");
  // A response lost after commit returns the stored receipt and changes nothing.
  if("APPLIED".equals(row.status))return view(row);
  if(!"DRAFT".equals(row.status))throw conflict("This draft is canceled");
  if(row.version!=approval.version())throw conflict("The change set changed; review its current preview");
  if(row.expiresAt<=System.currentTimeMillis())throw new ResponseStatusException(HttpStatus.GONE,"Approval expired; refresh this draft and review again");
  Request request=request(row);
  String current;
  try{current=RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(preview(request)));}
  catch(IllegalArgumentException e){throw conflict(CHANGED);}
  if(!current.equals(row.contentHash))throw conflict(CHANGED);
  int added=0,changed=0,removed=0;
  for(var op:request.operations())switch(op.type()){
   case ADD -> {alerts.addRoute(routeRequest(op),owner);added++;}
   case UPDATE -> {alerts.updateRoute(op.routeId(),routeRequest(op),owner);changed++;}
   case REMOVE -> {alerts.deleteRoute(op.routeId(),owner);removed++;}
  }
  long now=System.currentTimeMillis();
  var receipt=new LinkedHashMap<String,Object>();receipt.put("appliedAt",now);receipt.put("actor",owner);receipt.put("changeSetId",row.id);receipt.put("added",added);receipt.put("changed",changed);receipt.put("removed",removed);
  LOG.info("Alert route change set {} drafted by the assistant was applied by {}: {} added, {} changed, {} removed",row.id,owner,added,changed,removed);
  row.receiptJson=RuleDefinitionHistory.encode(receipt);row.appliedAt=now;row.status="APPLIED";records.flush();return view(row);
 }

 /** What each operation would do to the routes as they are right now; throws when a draft no longer fits them. */
 Preview preview(Request request){
  var changes=new ArrayList<Change>();Set<Long> touched=new HashSet<>();
  for(var op:request.operations()){
   switch(op.type()){
    case ADD -> {alerts.checkRoute(routeRequest(op));changes.add(new Change(Type.ADD,null,state(null,0,true,op)));}
    case UPDATE -> {
     var before=route(op,touched);alerts.checkRoute(routeRequest(op));
     changes.add(new Change(Type.UPDATE,state(before),state(before.getId(),before.getConfigurationVersion(),before.isEnabled(),op)));
    }
    case REMOVE -> {var before=route(op,touched);changes.add(new Change(Type.REMOVE,state(before),null));}
   }
  }
  return new Preview(List.copyOf(changes));
 }

 /** The route this operation names, only while it is still at the version the draft was made against. */
 private AlertRouteEntity route(Operation op,Set<Long> touched){
  Long id=op.routeId();
  if(id==null||!touched.add(id))throw new IllegalArgumentException("Each route can be changed once per draft.");
  var found=records.find(AlertRouteEntity.class,id);
  if(found==null)throw new IllegalArgumentException("No such route.");
  if(op.baseVersion()==null||found.getConfigurationVersion()!=op.baseVersion())throw new IllegalArgumentException(CHANGED);
  return found;
 }

 private RouteState state(AlertRouteEntity route){
  return new RouteState(route.getId(),route.getConfigurationVersion(),route.getAlertType(),route.getChannel().getId(),route.getChannel().getName(),route.getChannel().isEnabled(),route.isEnabled(),route.getMinPriority(),
    route.getApiLabelFilter(),route.getRepoInclude(),route.getRepoExclude(),route.getAggregation(),route.getDedupeWindowHours());
 }
 private RouteState state(Long routeId,long version,boolean enabled,Operation op){
  var channel=op.channelId()==null?null:records.find(AlertChannelEntity.class,op.channelId());
  if(channel==null)throw new IllegalArgumentException("Choose an existing channel.");
  return new RouteState(routeId,version,op.alertType(),channel.getId(),channel.getName(),channel.isEnabled(),enabled,op.minPriority(),StringUtils.trimToNull(op.apiLabelFilter()),
    StringUtils.trimToNull(op.repoInclude()),StringUtils.trimToNull(op.repoExclude()),op.aggregation(),op.dedupeWindowHours()==null?0:op.dedupeWindowHours());
 }
 static AlertSettingsService.RouteRequest routeRequest(Operation op){
  return new AlertSettingsService.RouteRequest(op.alertType(),op.channelId()==null?0:op.channelId(),op.minPriority(),op.apiLabelFilter(),op.repoInclude(),op.repoExclude(),
    op.aggregation(),op.dedupeWindowHours()==null?0:op.dedupeWindowHours());
 }

 private static void validateShape(Request request){
  if(request==null||request.operations()==null||request.operations().isEmpty()||request.operations().size()>MAX_OPERATIONS)throw new IllegalArgumentException("Use 1–"+MAX_OPERATIONS+" changes per draft");
  AssistantPersistence.uuid(request.idempotencyKey());
  for(var op:request.operations()){
   if(op==null||op.type()==null)throw new IllegalArgumentException("A change type is required");
   boolean existing=op.type()!=Type.ADD;
   if(existing&&op.routeId()==null||!existing&&op.routeId()!=null)throw new IllegalArgumentException("Only an existing route is named by id");
  }
 }
 private AlertRouteChangeSetEntity owned(String id,String owner,boolean lock){
  var row=lock?records.lock(AlertRouteChangeSetEntity.class,AssistantPersistence.uuid(id)):records.find(AlertRouteChangeSetEntity.class,AssistantPersistence.uuid(id));
  if(row==null||!owner.equals(row.owner))throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Change set unavailable");
  return row;
 }
 private static Request request(AlertRouteChangeSetEntity row){return parse(row.requestJson,Request.class);}
 private View view(AlertRouteChangeSetEntity row){
  return new View(row.id,row.version,row.status,row.contentHash,row.expiresAt,parse(row.previewJson,Preview.class),row.receiptJson==null?null:parse(row.receiptJson,Object.class));
 }
 private static <T>T parse(String json,Class<T> type){try{return RuleDefinitionHistory.JSON.readValue(json,type);}catch(Exception e){throw new IllegalStateException("Stored alert change set is unavailable",e);}}
 private static ResponseStatusException conflict(String message){return new ResponseStatusException(HttpStatus.CONFLICT,message);}
}

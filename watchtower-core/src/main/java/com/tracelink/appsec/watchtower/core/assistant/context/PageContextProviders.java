package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.assistant.SecretLooks;
import com.tracelink.appsec.watchtower.core.assistant.digest.HomeDigestService;
import com.tracelink.appsec.watchtower.core.assistant.features.JobDiagnosisService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.metrics.HomeDashboardService;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

/**
 * Cards for the pages that are not one finding, repository, pull request or rule: Home, the repository list, alert
 * settings, jobs, one scan type's metrics and the scanner modules. Each holds counts and a few names; never a finding, a
 * file, a person or a webhook address. These pages name no ids, so the page sends only its kind.
 */
public final class PageContextProviders {
 private PageContextProviders() { }
 private static final String WITHHELD="(withheld)";
 /** A name written by a person, withheld whole when it looks like a secret. */
 static String safeName(Object name){
  String text=String.valueOf(name);
  if(SecretLooks.looksLikeSecret(text))return WITHHELD;
  return text.length()>MAX_NAME?text.substring(0,MAX_NAME):text;
 }
 private static final int MAX_NAME=40;
 private static long count(LedgerRepository records,String jpql,Object... parameters){Long n=records.scalar(Long.class,jpql,parameters);return n==null?0:n;}

 /** Home: this week against last week, integrations and waiting requests, as the weekly digest sees them. */
 @Component public static class Home implements ContextProvider {
  private final HomeDigestService digests;
  public Home(HomeDigestService digests){this.digests=digests;}
  @Override public String kind(){return "home";}
  @Override public Set<String> grants(){return Set.of("Scan Dashboard View");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){return ContextCard.ok(kind(),"Page · Home",digests.currentCounts(),Map.of());}
 }

 /** The repository list: how many there are and how many have a ruleset; no names. */
 @Component public static class Repositories implements ContextProvider {
  private final LedgerRepository records;
  public Repositories(LedgerRepository records){this.records=records;}
  @Override public String kind(){return "repositories";}
  @Override public Set<String> grants(){return Set.of("Repository Settings View");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){
   var facts=new LinkedHashMap<String,Object>();
   facts.put("repositories",count(records,"SELECT COUNT(r) FROM RepositoryEntity r"));
   facts.put("with_ruleset",count(records,"SELECT COUNT(r) FROM RepositoryEntity r WHERE r.ruleset IS NOT NULL"));
   facts.put("without_ruleset",count(records,"SELECT COUNT(r) FROM RepositoryEntity r WHERE r.ruleset IS NULL"));
   facts.put("scanning_paused",count(records,"SELECT COUNT(r) FROM RepositoryEntity r WHERE r.scanningPaused=true"));
   return ContextCard.ok(kind(),"Page · Repositories",facts,Map.of());
  }
 }

 /** Alert settings: channel names and whether they are on, and routes by alert type. Never a webhook address. */
 @Component public static class AlertSettings implements ContextProvider {
  static final int MAX_CHANNELS=10,MAX_TYPES=12;
  private final LedgerRepository records;
  public AlertSettings(LedgerRepository records){this.records=records;}
  @Override public String kind(){return "alert_settings";}
  @Override public Set<String> grants(){return Set.of("Alert Settings View");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){
   var facts=new LinkedHashMap<String,Object>();
   facts.put("channels",count(records,"SELECT COUNT(c) FROM AlertChannelEntity c"));
   var names=new ArrayList<Map<String,Object>>();
   for(var row:records.maps("SELECT c.name AS name,c.enabled AS enabled FROM AlertChannelEntity c ORDER BY c.name",0,MAX_CHANNELS))names.add(Map.of("name",safeName(row.get("name")),"enabled",row.get("enabled")));
   facts.put("channel_names",names);
   facts.put("routes",count(records,"SELECT COUNT(r) FROM AlertRouteEntity r"));
   facts.put("routes_enabled",count(records,"SELECT COUNT(r) FROM AlertRouteEntity r WHERE r.enabled=true"));
   var byType=new LinkedHashMap<String,Object>();
   for(var row:records.maps("SELECT r.alertType AS type,COUNT(r) AS n FROM AlertRouteEntity r GROUP BY r.alertType ORDER BY r.alertType",0,MAX_TYPES))byType.put(String.valueOf(row.get("type")),row.get("n"));
   facts.put("routes_by_type",byType);
   return ContextCard.ok(kind(),"Page · Alert settings",facts,Map.of());
  }
 }

 /** Jobs on the Queue page: how many wait, run or failed lately, and the last few failures in cleaned-up words. */
 @Component public static class Jobs implements ContextProvider {
  static final int RECENT_FAILURES=3,MAX_ERROR=120;
  static final long DAY_MILLIS=24*3600*1000L;
  private final LedgerRepository records;
  public Jobs(LedgerRepository records){this.records=records;}
  /** A coarse age keeps the card the same from one question to the next. */
  static String age(long millis){return millis<3600_000L?"within the hour":millis<DAY_MILLIS?"today":"earlier";}
  @Override public String kind(){return "jobs";}
  @Override public Set<String> grants(){return Set.of("Scan Results View");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){
   var types=new ArrayList<>(JobDiagnosisService.DIAGNOSABLE);long now=System.currentTimeMillis(),since=now-DAY_MILLIS;
   var facts=new LinkedHashMap<String,Object>();
   facts.put("queued",count(records,"SELECT COUNT(j) FROM AsyncJobEntity j WHERE j.type IN (?1) AND j.status=?2",types,AsyncJobStatus.QUEUED));
   facts.put("running",count(records,"SELECT COUNT(j) FROM AsyncJobEntity j WHERE j.type IN (?1) AND j.status=?2",types,AsyncJobStatus.RUNNING));
   facts.put("failed_24h",count(records,"SELECT COUNT(j) FROM AsyncJobEntity j WHERE j.type IN (?1) AND j.status=?2 AND j.createdAt>=?3",types,AsyncJobStatus.FAILED,since));
   facts.put("done_24h",count(records,"SELECT COUNT(j) FROM AsyncJobEntity j WHERE j.type IN (?1) AND j.status=?2 AND j.createdAt>=?3",types,AsyncJobStatus.DONE,since));
   var recent=new ArrayList<Map<String,Object>>();
   for(var row:records.maps("SELECT j.type AS type,j.createdAt AS created,j.error AS error FROM AsyncJobEntity j WHERE j.type IN (?1) AND j.status=?2 ORDER BY j.createdAt DESC",0,RECENT_FAILURES,types,AsyncJobStatus.FAILED)){
    var failure=new LinkedHashMap<String,Object>();
    failure.put("job",((AsyncJobType)row.get("type")).getDisplayName());
    failure.put("when",age(now-((Number)row.get("created")).longValue()));
    failure.put("error",JobDiagnosisService.clean((String)row.get("error"),MAX_ERROR));
    recent.add(failure);
   }
   facts.put("recent_failures",recent);
   return ContextCard.ok(kind(),"Page · Jobs",facts,Map.of());
  }
 }

 /** One scan type's dashboard: scans and findings in total and scans today. */
 @Component public static class Metrics implements ContextProvider {
  private final MetricsCacheService metrics;
  public Metrics(MetricsCacheService metrics){this.metrics=metrics;}
  @Override public String kind(){return "metrics";}
  @Override public Set<String> grants(){return Set.of("Scan Dashboard View");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){
   ScanType type=find(ids.scanType());
   if(type==null)return ContextCard.unavailable(kind());
   var facts=new LinkedHashMap<String,Object>();
   facts.put("scan_type",type.getDisplayName());facts.put("scans",metrics.getScanCount(type));facts.put("scans_today",metrics.getScanCountToday(type));facts.put("findings",metrics.getViolationCount(type));
   return ContextCard.ok(kind(),"Page · Metrics ("+type.getDisplayName()+")",facts,ContextService.idMap(new ContextRequest.Ids(type.getTypeName(),null,null,null,null)));
  }
  static ScanType find(String name){
   if(name==null)return null;
   for(ScanType type:CodeScanType.values())if(type.getTypeName().equals(name))return type;
   for(ScanType type:ImageScanType.values())if(type.getTypeName().equals(name))return type;
   return null;
  }
 }

 /** The scanner modules: each one's state and which files it runs on (empty means every file). */
 @Component public static class ScannerModules implements ContextProvider {
  static final int MAX_MODULES=12,MAX_TYPES=6;
  private final HomeDashboardService home;private final ModuleControlService controls;
  public ScannerModules(HomeDashboardService home,ModuleControlService controls){this.home=home;this.controls=controls;}
  @Override public String kind(){return "scanner_modules";}
  @Override public Set<String> grants(){return Set.of("Module Settings Modify");}
  @Override public ContextCard resolve(ContextRequest.Ids ids){
   var modules=new ArrayList<Map<String,Object>>();long ready=0,setup=0,off=0;
   for(var status:home.getModuleStatuses()){
    switch(String.valueOf(status.state())){case "ready"->ready++;case "setup"->setup++;default->off++;}
    if(modules.size()>=MAX_MODULES)continue;
    var module=new LinkedHashMap<String,Object>();module.put("name",safeName(status.name()));module.put("state",status.state());
    var fileTypes=controls.policy(status.name()).fileTypes();
    module.put("runs_on",fileTypes==null?"its default files":fileTypes.isEmpty()?"every file":fileTypes.stream().limit(MAX_TYPES).map(PageContextProviders::safeName).toList());
    modules.add(module);
   }
   var facts=new LinkedHashMap<String,Object>();
   facts.put("ready",ready);facts.put("needs_setup",setup);facts.put("off",off);facts.put("modules",modules);
   return ContextCard.ok(kind(),"Page · Scanner modules",facts,Map.of());
  }
 }
}

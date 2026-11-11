package com.tracelink.appsec.watchtower.core.rule.report;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDate;
import java.time.temporal.IsoFields;
import java.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.LanguageScopedRule;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Weekly, report-only review summary (plan R5.1). Reads stewardship and the precomputed health
 * rollup; never opens review items or changes enforcement. One scheduled report per ISO week.
 */
@Service
public class RuleReviewReportService {
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(RuleReviewReportService.class);
 private static final String LOCK="rule-review-reports";
 private static final long MANUAL_INTERVAL_MILLIS=5*60*1000L;
 private static final int RETAINED=12,MAX_SUMMARY_BYTES=512*1024,MAX_RULES=50000,ID_CHUNK=500;
 /** The rollup refreshes every minute; older evidence is treated as missing rather than current. */
 private static final long STALE_HEALTH_MILLIS=2*24*60*60*1000L;
 private static final long THEME_WINDOW_MILLIS=90*24*60*60*1000L;
 private static final int MAX_SIGNALS=20000;
 private static final ObjectMapper MAPPER=new ObjectMapper();
 private final LedgerRepository records;private final RuleReviewReportSettingsRepository settings;private final RuleReviewReportRepository reports;
 private final RuleService rules;private final Clock clock;private final RuleReviewReport.Catalog catalog=RuleReviewReport.Catalog.load();
 @Autowired
 public RuleReviewReportService(LedgerRepository records,RuleReviewReportSettingsRepository settings,RuleReviewReportRepository reports,RuleService rules){this(records,settings,reports,rules,Clock.systemUTC());}
 public RuleReviewReportService(LedgerRepository records,RuleReviewReportSettingsRepository settings,RuleReviewReportRepository reports,RuleService rules,Clock clock){
  this.records=records;this.settings=settings;this.reports=reports;this.rules=rules;this.clock=clock;
 }
 /** Hourly check on one pod; the unique ISO-week key keeps retries and other pods idempotent. */
 @Scheduled(cron="${watchtower.rule-review.report-cron:0 17 * * * *}",zone="UTC")
 @SchedulerLock(name="ruleReviewReport",lockAtMostFor="PT15M")
 @Transactional
 public void scheduled(){
  var current=current();LocalDate today=LocalDate.now(clock);
  // On or after the configured day: a missed day (all pods down, failure) is caught up later that week.
  if(!current.isEnabled()||today.getDayOfWeek().getValue()<current.getWeekday())return;
  String period=String.format(Locale.ROOT,"%d-W%02d",today.get(IsoFields.WEEK_BASED_YEAR),today.get(IsoFields.WEEK_OF_WEEK_BASED_YEAR));
  records.lockScope(LOCK);if(reports.existsByPeriodKey(period))return;
  store(period,"SCHEDULED","system",current.getVersion());
 }
 @Transactional
 public String runNow(String actor){
  records.lockScope(LOCK);
  Long last=records.scalar(Long.class,"SELECT MAX(r.createdAt) FROM RuleReviewReportEntity r WHERE r.triggerType='MANUAL'");
  if(last!=null&&clock.millis()-last<MANUAL_INTERVAL_MILLIS)throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"A report was run in the last 5 minutes");
  return store(null,"MANUAL",actor,current().getVersion());
 }
 @Transactional
 public void change(boolean enabled,int weekday,long version,String actor){
  if(weekday<1||weekday>7)throw new IllegalArgumentException("Weekday must be 1 (Monday) to 7 (Sunday)");
  var row=current();if(row.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"Report settings changed; reload");
  row.change(enabled,weekday,actor,clock.millis());settings.saveAndFlush(row);
  LOG.info("Rule review report settings changed by {}: enabled={}, weekday={}",actor,enabled,weekday);
 }
 @Transactional(readOnly=true)
 public Map<String,Object> latest(){
  var current=current();Map<String,Object> view=new LinkedHashMap<>();
  view.put("enabled",current.isEnabled());view.put("weekday",current.getWeekday());view.put("version",current.getVersion());view.put("updated_by",current.getUpdatedBy());view.put("updated_at",current.getUpdatedAt());
  Map<String,Object> result=new LinkedHashMap<>();result.put("settings",view);result.put("report",reports.findFirstByOrderByCreatedAtDesc().map(this::view).orElse(null));return result;
 }
 public record SavedReport(String id,String period,String trigger,String actor,long createdAt,boolean completeItems) { public String createdAtUtc(){return java.time.Instant.ofEpochMilli(createdAt).toString();} public String label(){return RuleReportPresentation.periodLabel(period);} public boolean scheduled(){return "SCHEDULED".equals(trigger);} }
 public record AttentionPage(com.tracelink.appsec.watchtower.core.mvc.PagedResult<RuleReviewReportItemEntity.Item> rows,boolean complete,boolean legacyTruncated) { }
 @Transactional(readOnly=true)
 public Map<String,Object> saved(String id){var data=new LinkedHashMap<>(latest());data.put("report",view(requireReport(id)));return data;}
 private RuleReviewReportEntity requireReport(String id){return reports.findById(UUID.fromString(id).toString()).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Saved report unavailable"));}
 @Transactional(readOnly=true)
 public List<SavedReport> history(){return records.list(RuleReviewReportEntity.class,"SELECT r FROM RuleReviewReportEntity r ORDER BY r.createdAt DESC,r.reportId DESC",0,24).stream().map(r->new SavedReport(r.getReportId(),r.getPeriodKey(),r.getTriggerType(),r.getActor(),r.getCreatedAt(),r.getItemSchema()==1)).toList();}
 @Transactional(readOnly=true)
 @SuppressWarnings("unchecked")
 public AttentionPage attention(String id,String search,String reason,int page,int size){
  com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.bounds(page,size);
  String pattern=com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.pattern(search);
  String attribute=switch(reason){case "all"->null;case "CONFIRMED_NOISE"->"reviewedNoise";case "REVIEW_OVERDUE"->"reviewOverdue";case "NO_OWNER"->"missingOwner";case "NO_RECENT_MATCHES"->"zeroMatches";case "NO_CWE"->"missingCwe";default->throw new IllegalArgumentException("Invalid attention reason");};
  var report=requireReport(id);
  if(report.getItemSchema()==1){
   String from="FROM RuleReviewReportItemEntity i WHERE i.reportId=?1 AND (LOWER(i.name) LIKE ?2 ESCAPE '!' OR LOWER(COALESCE(i.owner,'')) LIKE ?2 ESCAPE '!')"+(attribute==null?"":" AND i."+attribute+"=TRUE");
   long total=records.scalar(Long.class,"SELECT COUNT(i) "+from,id,pattern);
   var rows=records.list(RuleReviewReportItemEntity.class,"SELECT i "+from+" ORDER BY i.itemOrder",page*size,size,id,pattern).stream().map(RuleReviewReportItemEntity::view).toList();
   return new AttentionPage(com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.page(rows,page,size,total),true,false);
  }
  var summary=(Map<String,Object>)view(report).get("summary");var retained=(List<Map<String,Object>>)summary.getOrDefault("attention",List.of());String query=Objects.toString(search,"").trim().toLowerCase(Locale.ROOT);
  var items=retained.stream().map(row->legacyItem(id,row)).filter(item->(Objects.toString(item.name(),"")+" "+Objects.toString(item.owner(),"")).toLowerCase(Locale.ROOT).contains(query)).filter(item->"all".equals(reason)||item.reasons().stream().anyMatch(r->r.code().equals(reason))).toList();
  return new AttentionPage(com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.page(items.stream().skip((long)page*size).limit(size).toList(),page,size,items.size()),false,Boolean.TRUE.equals(summary.get("attention_truncated")));
 }
 /** How many saved attention rows carry each reason code; a legacy report counts its retained sample. */
 @Transactional(readOnly=true)
 @SuppressWarnings("unchecked")
 public Map<String,Long> reasonCounts(String id){
  var report=requireReport(id);Map<String,Long> counts=new LinkedHashMap<>();
  if(report.getItemSchema()==1){
   var row=records.maps("SELECT COALESCE(SUM(CASE WHEN i.reviewedNoise=TRUE THEN 1 ELSE 0 END),0) AS confirmed_noise,COALESCE(SUM(CASE WHEN i.reviewOverdue=TRUE THEN 1 ELSE 0 END),0) AS review_overdue,COALESCE(SUM(CASE WHEN i.missingOwner=TRUE THEN 1 ELSE 0 END),0) AS no_owner,COALESCE(SUM(CASE WHEN i.zeroMatches=TRUE THEN 1 ELSE 0 END),0) AS no_recent_matches,COALESCE(SUM(CASE WHEN i.missingCwe=TRUE THEN 1 ELSE 0 END),0) AS no_cwe FROM RuleReviewReportItemEntity i WHERE i.reportId=?1",0,1,id).getFirst();
   row.forEach((key,value)->counts.put(key.toUpperCase(Locale.ROOT),value instanceof Number n?n.longValue():0L));
   return counts;
  }
  var summary=(Map<String,Object>)view(report).get("summary");
  for(var item:(List<Map<String,Object>>)summary.getOrDefault("attention",List.of()))
   for(var reason:(List<Map<String,Object>>)item.getOrDefault("reasons",List.of()))counts.merge((String)reason.get("code"),1L,Long::sum);
  return counts;
 }
 private static RuleReviewReportItemEntity.Item legacyItem(String id,Map<String,Object> row){var item=RuleReviewReportItemEntity.from(id,0,row);if(item.zeroMatches)item.successfulEngines=null;return item.view();}
 private RuleReviewReportSettingsEntity current(){return settings.findById(RuleReviewReportSettingsEntity.ID).orElseThrow(()->new IllegalStateException("Review report settings missing; apply migrations"));}
 private String store(String period,String trigger,String actor,long settingsVersion){
  var stale=new long[1];var facts=facts(stale);var today=LocalDate.now(clock);var summary=RuleReviewReport.build(facts,signals(),catalog,today);var attention=RuleReviewReport.attention(facts,today);
  @SuppressWarnings("unchecked") var counts=(Map<String,Object>)summary.get("counts");counts.put("stale_health",stale[0]);
  String json=fit(summary);
  String id=UUID.randomUUID().toString();var report=new RuleReviewReportEntity(id,period,trigger,actor,settingsVersion,clock.millis(),json);report.withCompleteItems();records.insert(report);
  for(int index=0;index<attention.size();index++)records.insert(RuleReviewReportItemEntity.from(id,index,attention.get(index)));
  // Separate pools: frequent manual runs can never evict the current week's scheduled report.
  var expired=records.maps("SELECT r.reportId AS report_id FROM RuleReviewReportEntity r WHERE r.triggerType=?1 ORDER BY r.createdAt DESC,r.reportId DESC",RETAINED,1000,trigger).stream().map(r->(String)r.get("report_id")).toList();
  if(!expired.isEmpty()){records.update("DELETE FROM RuleReviewReportItemEntity i WHERE i.reportId IN ?1",expired);reports.deleteAllByIdInBatch(expired);}
  LOG.info("Rule review report {} created ({}) by {}",id,trigger,actor);return id;
 }
 /** Halves the attention list until the summary fits; the matrix is already bounded by the builder. */
 @SuppressWarnings("unchecked")
 private static String fit(Map<String,Object> summary){
  try{
   String json=MAPPER.writeValueAsString(summary);
   while(json.getBytes(StandardCharsets.UTF_8).length>MAX_SUMMARY_BYTES){
    var attention=(List<Map<String,Object>>)summary.get("attention");if(attention.isEmpty())throw new IllegalStateException("Review report exceeds its size limit");
    summary.put("attention",List.copyOf(attention.subList(0,attention.size()/2)));summary.put("attention_truncated",true);json=MAPPER.writeValueAsString(summary);
   }
   return json;
  }catch(JsonProcessingException e){throw new IllegalStateException("Review report serialization failed",e);}
 }
 private List<RuleReviewReport.RuleFacts> facts(long[] staleRows){
  var all=rules.getRules();Map<String,String> health=new HashMap<>();long freshAfter=clock.millis()-STALE_HEALTH_MILLIS;
  var ids=all.stream().map(r->r.getId()).filter(Objects::nonNull).distinct().toList();
  // Only rows for current rules, in bounded chunks: nothing is silently dropped by a global cap.
  for(int from=0;from<ids.size();from+=ID_CHUNK){
   for(var row:records.maps("SELECT h.ruleId AS rule_id,h.revisionKey AS revision_key,h.computedAt AS computed_at,h.evidenceJson AS evidence_json FROM RuleHealthEntity h WHERE h.ruleId IN ?1",0,Integer.MAX_VALUE,ids.subList(from,Math.min(ids.size(),from+ID_CHUNK)))){
    if(row.get("computed_at") instanceof Number at&&at.longValue()<freshAfter){staleRows[0]++;continue;}
    health.put(row.get("rule_id")+"/"+row.get("revision_key"),(String)row.get("evidence_json"));
   }
  }
  Map<Long,Long> open=new HashMap<>();
  for(var row:records.maps("SELECT r.ruleId AS rule_id,COUNT(r) AS open_reviews FROM RuleReviewItemEntity r WHERE r.status IN ('OPEN','IN_REVIEW') GROUP BY r.ruleId",0,MAX_RULES))
   open.put(((Number)row.get("rule_id")).longValue(),((Number)row.get("open_reviews")).longValue());
  List<RuleReviewReport.RuleFacts> facts=new ArrayList<>();
  for(var rule:all){
   var stewardship=rule.getStewardship();String revision=rule.getRevision();var evidence=evidence(health.get(rule.getId()+"/"+(revision==null?"unknown":revision)));
   facts.add(new RuleReviewReport.RuleFacts(rule.getId(),rule.getName(),rule.getModule(),rule.getPriority(),stewardship.getState(),stewardship.getOwner(),stewardship.getReviewBy(),stewardship.getCwe(),
     rule instanceof LanguageScopedRule scoped?scoped.scannedLanguages():Set.of(),evidence.get("90d"),evidence.get("30d"),open.getOrDefault(rule.getId(),0L),revision,stewardship.isNotSecurity()));
  }
  return facts;
 }
 /** Human feedback for R5.2 themes: bounded, newest first, ids and short text only. */
 private List<FeedbackThemes.Signal> signals(){
  long since=clock.millis()-THEME_WINDOW_MILLIS;List<FeedbackThemes.Signal> signals=new ArrayList<>();
  for(var r:records.maps("SELECT f.ruleId AS rule_id,f.disposition AS category,f.occurrenceKey AS id,f.reviewer AS actor,f.updatedAt AS at,f.explanation AS text FROM FindingFeedbackEntity f WHERE f.judgment='FALSE_POSITIVE' AND f.ruleId IS NOT NULL AND f.updatedAt>=?1 ORDER BY f.updatedAt DESC",0,MAX_SIGNALS,since))
   signals.add(signal(r,"finding_feedback",String.valueOf(r.get("category"))));
  // One signal per bypass and rule, however many findings that bypass covered.
  for(var r:records.maps("SELECT DISTINCT v.ruleId AS rule_id,b.reasonCode AS category,b.id AS id,b.bypassedBy AS actor,b.createdAt AS at,b.reason AS text FROM PullRequestBypassEntity b JOIN BypassFindingIdentityEntity v ON v.bypassId=b.id WHERE v.ruleId IS NOT NULL AND b.createdAt>=?1 ORDER BY b.createdAt DESC",0,MAX_SIGNALS,since))
   signals.add(signal(r,"bypass",r.get("category")==null?"UNSPECIFIED":String.valueOf(r.get("category"))));
  for(var r:records.maps("SELECT i.ruleId AS rule_id,i.status AS status,i.reason AS reason,i.reviewId AS id,i.owner AS actor,i.updatedAt AS at,i.outcome AS text FROM RuleReviewItemEntity i WHERE i.status IN ('ACCEPTED','REJECTED') AND i.updatedAt>=?1 ORDER BY i.updatedAt DESC",0,MAX_SIGNALS,since))
   signals.add(signal(r,"review_outcome",r.get("status")+":"+r.get("reason")));
  return signals;
 }
 private static FeedbackThemes.Signal signal(Map<String,Object> row,String source,String category){
  return new FeedbackThemes.Signal(((Number)row.get("rule_id")).longValue(),source,category,String.valueOf(row.get("id")),(String)row.get("actor"),((Number)row.get("at")).longValue(),(String)row.get("text"));
 }
 private static Map<String,Map<String,Object>> evidence(String json){
  if(json==null)return Map.of();
  try{return MAPPER.readValue(json,new TypeReference<Map<String,Map<String,Object>>>(){});}
  catch(JsonProcessingException e){LOG.warn("Unreadable rule health rollup row; treated as missing evidence");return Map.of();}
 }
 private Map<String,Object> view(RuleReviewReportEntity report){
  Map<String,Object> view=new LinkedHashMap<>();
  view.put("id",report.getReportId());view.put("period",report.getPeriodKey());view.put("trigger",report.getTriggerType());view.put("actor",report.getActor());
  view.put("complete_items",report.getItemSchema()==1);view.put("created_at",report.getCreatedAt());view.put("settings_version",report.getSettingsVersion());
  try{view.put("summary",MAPPER.readValue(report.getSummaryJson(),new TypeReference<Map<String,Object>>(){}));}catch(JsonProcessingException e){throw new IllegalStateException("Stored review report unreadable",e);}
  return view;
 }
}

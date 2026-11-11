package com.tracelink.appsec.watchtower.core.metrics;

import java.util.*;
import java.time.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/** Same occurrence/revision/window units; reviewed findings are a selected sample, not precision. */
@Service
public class RuleHealthService {
 /** Chip names are part of the rollup contract; the weekly review report reads them. */
 public static final String NO_RECENT_MATCHES="No recent matches",INSUFFICIENT_DATA="Insufficient data/coverage",NEEDS_REVIEW="Needs review";
 private final LedgerRepository records;private final int minSample,minFp;private final double threshold;
 public RuleHealthService(LedgerRepository records,@Value("${watchtower.rule-health.minimum-sample:6}")int minSample,
  @Value("${watchtower.rule-health.minimum-fp:3}")int minFp,@Value("${watchtower.rule-health.fp-rate:0.5}")double threshold){if(minSample<1||minFp<1||!Double.isFinite(threshold)||threshold<0||threshold>1)throw new IllegalArgumentException("Invalid health thresholds");this.records=records;this.minSample=minSample;this.minFp=minFp;this.threshold=threshold;}
 /** The noise thresholds, shared with the rule work overview so both pages agree. */
 public int minimumSample(){return minSample;}
 public int minimumFalsePositives(){return minFp;}
 public double falsePositiveRate(){return threshold;}
 @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
 public Map<String,Object> health(long ruleId,String revision,int days,String type) {return health(ruleId,revision,days,type,"all");}
 @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
 public Map<String,Object> health(long ruleId,String revision,int days,String type,String policy) {
  if(ruleId<=0||days<1||days>90||!Set.of("all","pull_request","upload","repository").contains(type)||!Set.of("all","blocking","nonblocking","unknown").contains(policy)||revision!=null&&!revision.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Invalid health scope");
  long now=System.currentTimeMillis(),since=Instant.ofEpochMilli(now).atZone(ZoneOffset.UTC).toLocalDate().minusDays(days-1).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  List<Object> args=new ArrayList<>();args.add(ruleId);if(revision!=null)args.add(revision);args.add(since);if(!"all".equals(type))args.add(type);
  var counts=records.maps("SELECT COALESCE(SUM(m.findings),0) AS findings,COALESCE(SUM(m.blocking),0) AS blocking,COALESCE(SUM(m.blockingUnknown),0) AS blocking_unknown,SUM(m.opportunities) AS known_opportunities,MAX(m.lastFired) AS last_fired,COUNT(m) AS selected_scans,COALESCE(SUM(CASE WHEN m.engineStatus='RAN' THEN 1 ELSE 0 END),0) AS successful_engine_scans,COALESCE(SUM(CASE WHEN m.coverage='FAILED' THEN 1 ELSE 0 END),0) AS failed_scans,COALESCE(SUM(CASE WHEN m.coverage IN ('SKIPPED','UNSUPPORTED','DISABLED') THEN 1 ELSE 0 END),0) AS skipped_scans,COALESCE(SUM(CASE WHEN m.coverage='UNKNOWN' THEN 1 ELSE 0 END),0) AS unknown_scans FROM RuleMetricScanEntity m WHERE "+scope("m","bucketStart",revision,type),0,1,args.toArray()).getFirst();
  String feedback=scope("f","occurredAt",revision,type)+switch(policy){case "blocking"->" AND f.effectiveBlocking=TRUE";case "nonblocking"->" AND f.effectiveBlocking=FALSE";case "unknown"->" AND f.effectiveBlocking IS NULL";default->"";};
  String matched="EXISTS (SELECT m.scanId FROM RuleMetricScanEntity m WHERE m.scanType=f.scanType AND m.scanId=f.scanId AND m.ruleId=f.ruleId AND (m.revision=f.revision OR (m.revision IS NULL AND f.revision IS NULL)))";
  var labels=records.maps("SELECT COALESCE(SUM(CASE WHEN f.judgment='TRUE_POSITIVE' THEN 1 ELSE 0 END),0) AS tp,COALESCE(SUM(CASE WHEN f.judgment='FALSE_POSITIVE' THEN 1 ELSE 0 END),0) AS fp,COALESCE(SUM(CASE WHEN f.judgment='UNKNOWN' THEN 1 ELSE 0 END),0) AS unknown_judgments FROM FindingFeedbackEntity f WHERE "+feedback+" AND "+matched,0,1,args.toArray()).getFirst();
  long excluded=records.scalar(Long.class,"SELECT COUNT(f) FROM FindingFeedbackEntity f WHERE "+feedback+" AND NOT "+matched,args.toArray());
  labels.put("unknown",labels.remove("unknown_judgments"));
  long allFindings=n(counts,"findings");
  if(!"all".equals(policy)){
   long scoped=switch(policy){case "blocking"->n(counts,"blocking");case "unknown"->n(counts,"blocking_unknown");default->allFindings-n(counts,"blocking")-n(counts,"blocking_unknown");};counts.put("findings",scoped);counts.put("known_opportunities",null);
   String expression=switch(policy){case "blocking"->"m.blocking";case "unknown"->"m.blockingUnknown";default->"m.findings-m.blocking-m.blockingUnknown";};
   counts.put("last_fired",records.scalar(Long.class,"SELECT MAX(CASE WHEN "+expression+">0 THEN m.lastFired ELSE NULL END) FROM RuleMetricScanEntity m WHERE "+scope("m","bucketStart",revision,type),args.toArray()));
  }
  long tp=n(labels,"tp"),fp=n(labels,"fp"),sample=tp+fp,findings=n(counts,"findings");Double rate=sample==0?null:(double)fp/sample;
  Map<String,Object> result=new LinkedHashMap<>(counts);result.putAll(labels);result.put("rule_id",ruleId);result.put("revision",revision);result.put("days",days);result.put("since",since);result.put("scan_type",type);result.put("computed_at",now);result.put("reviewed_sample",sample);result.put("reviewed_fp_rate",rate);
  result.put("policy",policy);result.put("all_policy_findings",allFindings);result.put("excluded_reviews",excluded);
  result.put("review_coverage",findings==0||sample>findings?null:(double)sample/findings);result.put("coverage_note","Selected rules are not proof of evaluation; informational findings are included. Rates describe reviewed occurrences, not overall precision. Reused/unprojected scans are excluded from both execution counts and review samples. Blocking/unknown counts and scan coverage describe all policies; evaluated opportunities are unknown for filtered policy scopes.");
  String evidenceState=n(counts,"selected_scans")==0?"NO_ELIGIBLE_EVIDENCE":findings>0?"RECORDED_MATCHES":n(counts,"successful_engine_scans")>0?"SUCCESSFUL_ENGINE_ZERO_MATCHES":"UNVERIFIED_ZERO_MATCHES";
  result.put("evidence_state",evidenceState);
  result.put("evidence_note",switch(evidenceState){case "NO_ELIGIBLE_EVIDENCE"->"No eligible execution projection exists for this revision and scope. The cause is unknown; this does not establish a clean scan or data loss.";case "SUCCESSFUL_ENGINE_ZERO_MATCHES"->"A relevant engine completed successfully with no recorded matches in this scope. Per-rule evaluation is not certified.";case "UNVERIFIED_ZERO_MATCHES"->"No matches were recorded, but successful engine execution is unverified for this scope.";default->"Matches were recorded. Review the execution coverage and reviewed sample before drawing conclusions about rule quality.";});
  List<String> chips=new ArrayList<>();if(findings==0&&n(counts,"successful_engine_scans")>0)chips.add(NO_RECENT_MATCHES);if(sample<minSample||n(counts,"unknown_scans")>0||n(counts,"selected_scans")==0)chips.add(INSUFFICIENT_DATA);if(sample>=minSample&&fp>=minFp&&rate>=threshold)chips.add(NEEDS_REVIEW);
  var rule=records.find(RuleEntity.class,ruleId);if(rule!=null&&rule.getStewardship().getReviewBy()!=null&&rule.getStewardship().getReviewBy().isBefore(LocalDate.now(ZoneOffset.UTC)))chips.add("Review due");result.put("chips",chips);
  if("all".equals(type)||"pull_request".equals(type)) {
   result.put("bypass_events",revision==null?records.scalar(Long.class,"SELECT COUNT(DISTINCT b.id) FROM PullRequestBypassEntity b JOIN BypassFindingIdentityEntity v ON v.bypassId=b.id WHERE b.createdAt>=?1 AND v.ruleId=?2 AND v.revision IS NULL",since,ruleId):records.scalar(Long.class,"SELECT COUNT(DISTINCT b.id) FROM PullRequestBypassEntity b JOIN BypassFindingIdentityEntity v ON v.bypassId=b.id WHERE b.createdAt>=?1 AND v.ruleId=?2 AND v.revision=?3",since,ruleId,revision));
  }else result.put("bypass_events",0);
  return result;
 }
 /** Only trusted attribute names enter these fragments; every scope value remains bound. */
 private String scope(String alias,String time,String revision,String type) {
  int next=2;String filter=alias+".ruleId=?1 AND ";
  filter+=revision==null?alias+".revision IS NULL":alias+".revision=?"+next++;
  filter+=" AND "+alias+"."+time+">=?"+next++;
  if(!"all".equals(type))filter+=" AND "+alias+".scanType=?"+next;
  return filter;
 }
 public List<Map<String,Object>> revisions(long ruleId){
  if(ruleId<=0)throw new IllegalArgumentException("Invalid rule id");
  Set<String> revisions=new LinkedHashSet<>();var rule=records.find(RuleEntity.class,ruleId);if(rule!=null)revisions.add(rule.getStewardship().getRevision());
  for(String entity:List.of("RuleMetricScanEntity","FindingFeedbackEntity","RuleReviewItemEntity")) {
   for(var row:records.maps("SELECT DISTINCT revision AS revision FROM "+entity+" WHERE ruleId=?1",0,100,ruleId)){revisions.add((String)row.get("revision"));if(revisions.size()>=100)break;}
   if(revisions.size()>=100)break;
  }
  return revisions.stream().map(revision->{Map<String,Object> row=new LinkedHashMap<>();row.put("revision",revision);return row;}).toList();
 }
 private static long n(Map<String,Object> values,String key){Object v=values.get(key);return v instanceof Number num?num.longValue():0;}
}

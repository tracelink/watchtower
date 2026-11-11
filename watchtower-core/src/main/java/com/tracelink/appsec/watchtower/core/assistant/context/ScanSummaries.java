package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSecretFindings;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Counts for one scan, for page cards and the summary tool. Findings of secret rules are only counted,
 * never listed by rule or location. A scanner that had no file of its types ("not applicable") is shown
 * as not needed: it finished its part of the scan, so it is neither skipped nor failed.
 */
@Component
public class ScanSummaries {
 static final int MAX_RULES=10,MAX_ROWS=5000;
 private final LedgerRepository records;private final RepoScanRepository repoScans;private final RepoScanReportService reports;private final AssistantSecretFindings secrets;
 public ScanSummaries(LedgerRepository records,RepoScanRepository repoScans,RepoScanReportService reports,AssistantSecretFindings secrets){
  this.records=records;this.repoScans=repoScans;this.reports=reports;this.secrets=secrets;
 }
 /** A summary of a pull request or repository scan; anything else, or an unknown scan, is an IllegalArgumentException. */
 @Transactional(readOnly=true)
 public Map<String,Object> summary(String scanType,long scanId){
  if(scanId<1)throw new IllegalArgumentException("Unknown scan");
  return switch(scanType==null?"":scanType){
   case "pull_request"->pullRequest(scanId);
   case "repository"->repository(scanId);
   default->throw new IllegalArgumentException("Unsupported scan type");
  };
 }
 private Map<String,Object> pullRequest(long scanId){
  var scan=records.find(PullRequestScanEntity.class,scanId);
  if(scan==null)throw new IllegalArgumentException("Unknown scan");
  var secret=secrets.secretRules();
  var rows=records.maps("SELECT v.severity AS severity,v.violationName AS name,v.ruleIdentity.module AS module,v.ruleIdentity.ruleId AS rule_id,COUNT(v) AS n FROM PullRequestViolationEntity v WHERE v.scan.id=?1"
    +" GROUP BY v.severity,v.violationName,v.ruleIdentity.module,v.ruleIdentity.ruleId",0,MAX_ROWS+1,scanId);
  if(rows.size()>MAX_ROWS)throw new IllegalArgumentException("Too many rule groups to summarize");
  var counts=new Counts(secret);
  for(var row:rows)counts.add(row.get("severity")==null?null:String.valueOf(row.get("severity")),(String)row.get("name"),(String)row.get("module"),row.get("rule_id") instanceof Number id?id.longValue():null,((Number)row.get("n")).longValue());
  var container=scan.getContainer();var facts=new LinkedHashMap<String,Object>();
  facts.put("scan","pull_request");
  facts.put("repository",container.getRepoName());facts.put("pull_request",container.getPrId());
  facts.put("state",container.getClosedState()==null?"open":container.getClosedState().name().toLowerCase(Locale.ROOT));
  facts.put("blocked",scan.isBlocked());
  counts.into(facts);
  facts.put("engines",engines(scan.getExecutionSnapshotJson()==null?null:CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson())));
  return facts;
 }
 private Map<String,Object> repository(long scanId){
  var scan=repoScans.findById(scanId).orElseThrow(()->new IllegalArgumentException("Unknown scan"));
  var report=reports.getReport(scan).orElseThrow(()->new IllegalArgumentException("The scan report has expired"));
  var secret=secrets.secretRules();var counts=new Counts(secret);
  for(var f:report.findings()){
   var identity=f.ruleIdentity();
   counts.add(f.severity(),f.rule(),identity==null?null:identity.module(),identity==null?null:identity.ruleId(),1,Boolean.TRUE.equals(f.sensitive()));
  }
  var facts=new LinkedHashMap<String,Object>();
  facts.put("scan","repository");facts.put("repository",report.repository());facts.put("branch",report.branch());
  counts.into(facts);
  facts.put("engines",engines(report.executionSnapshot()));
  return facts;
 }
 /** How many scanners ran, how many had nothing to look at, and which did not finish. */
 static Map<String,Object> engines(CodeScanExecutionSnapshot snapshot){
  if(snapshot==null)return Map.of("recorded",false);
  long ran=0,notNeeded=0;var problems=new TreeMap<String,String>();
  for(var engine:snapshot.engines()){
   if(ScanExecutionSummary.NOT_APPLICABLE.equals(engine.status()))notNeeded++;
   else if(CodeScanExecutionSnapshot.completed(engine.status()))ran++;
   else problems.put(engine.scanner(),String.valueOf(engine.status()).toLowerCase(Locale.ROOT));
  }
  var map=new LinkedHashMap<String,Object>();
  map.put("recorded",true);map.put("ran",ran);map.put("not_needed",notNeeded);map.put("not_finished",problems);
  return map;
 }
 /** Counts by severity and rule, with secret findings reduced to a number. */
 private final class Counts {
  final AssistantSecretFindings.SecretRules secret;final Map<String,Long> bySeverity=new TreeMap<>();final Map<String,Long> byRule=new HashMap<>();long secrets;
  Counts(AssistantSecretFindings.SecretRules secret){this.secret=secret;}
  void add(String severity,String rule,String module,Long ruleId,long n){add(severity,rule,module,ruleId,n,false);}
  void add(String severity,String rule,String module,Long ruleId,long n,boolean flagged){
   if(flagged||secret.contains(ruleId,module,rule)){secrets+=n;return;}
   bySeverity.merge(severity==null?"UNKNOWN":severity,n,Long::sum);byRule.merge(rule==null?"unnamed":rule,n,Long::sum);
  }
  void into(Map<String,Object> facts){
   facts.put("findings_by_severity",bySeverity);
   facts.put("secret_findings",secrets);
   // A sum of the severities leaves the secret findings out, so the total is given outright.
   facts.put("total_findings",bySeverity.values().stream().mapToLong(Long::longValue).sum()+secrets);
   facts.put("total_findings_note","total_findings includes secret_findings, which are only counted, never described.");
   var top=new LinkedHashMap<String,Long>();
   byRule.entrySet().stream().sorted(Map.Entry.<String,Long>comparingByValue().reversed().thenComparing(Map.Entry::getKey)).limit(MAX_RULES).forEach(e->top.put(e.getKey(),e.getValue()));
   facts.put("top_rules",top);
  }
 }
}

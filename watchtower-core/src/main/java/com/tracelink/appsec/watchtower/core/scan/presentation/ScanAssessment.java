package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.*;
import com.tracelink.appsec.watchtower.core.scan.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;

/** Processing completion and assessment coverage are independent claims. */
public record ScanAssessment(String processing, String completeness, List<String> reasons) {
 public boolean complete() { return "COMPLETE".equals(completeness); }
 private static String processing(ScanStatus status) {
  return status==null?"UNKNOWN":switch(status){case DONE->"COMPLETED";case FAILED->"FAILED";case IN_PROGRESS->"RUNNING";case NOT_STARTED->"QUEUED";};
 }
 public static ScanAssessment of(ScanStatus status, CodeScanExecutionSnapshot snapshot, List<ProviderAssessmentReference> providers) {
  return of(status,snapshot,providers,Map.of());
 }
 /** As above; {@code failureReasons} says why a scanner failed, by the scanner's display name. */
 /**
  * As above for a scan that recorded which scanners ran but no rule snapshot (an upload): what ran,
  * failed or was skipped is known from the scanners, so it is not called an older scan.
  */
 public static ScanAssessment ofExecutions(ScanStatus status, List<ScanExecutionSummary.ScannerExecution> executions, List<ProviderAssessmentReference> providers) {
  String processing=processing(status);
  if(status!=ScanStatus.DONE && status!=null) return new ScanAssessment(processing,"INCOMPLETE",List.of("Processing has not completed successfully."));
  var reasons=new ArrayList<String>();
  if(providers.stream().anyMatch(p->p.status()==null||!p.status().complete()))reasons.add("A remote scanner (such as AWS) did not finish.");
  var why=failureReasons(executions);
  for(var execution:executions) {
   String name=ScannerIdentity.of(execution.scannerName()).name();
   // SKIPPED here means the ruleset has no rules for the scanner (the scan page lists it as "not used"), which is not a gap.
   if(Set.of("FAILED","DISABLED","UNSUPPORTED").contains(Objects.toString(execution.status(),""))) {
    String detail="FAILED".equals(execution.status())?why.get(name):null;
    reasons.add(name+" "+outcome(execution.status())+(detail==null||detail.isBlank()?"":" ("+detail+")")+".");
   }
  }
  if(!reasons.isEmpty()) return new ScanAssessment(processing,"INCOMPLETE",List.copyOf(reasons));
  return new ScanAssessment(processing,"UNKNOWN",List.of("Every scanner finished, but which rules ran was not recorded."));
 }
 public static ScanAssessment of(ScanStatus status, CodeScanExecutionSnapshot snapshot, List<ProviderAssessmentReference> providers, Map<String,String> failureReasons) {
  String processing=processing(status);
  var reasons=new ArrayList<String>();
  if(status!=ScanStatus.DONE && status!=null) return new ScanAssessment(processing,"INCOMPLETE",List.of("Processing has not completed successfully."));
  if(providers.stream().anyMatch(p->p.status()==null||!p.status().complete()))reasons.add("A remote scanner (such as AWS) did not finish.");
  if(snapshot==null) return new ScanAssessment(processing,reasons.isEmpty()?"UNKNOWN":"INCOMPLETE",reasons.isEmpty()?List.of("This older scan did not record which scanners ran."):reasons);
  boolean unknown=snapshot.schema()!=CodeScanExecutionSnapshot.SCHEMA || snapshot.engines().isEmpty();
  // Scanner and outcome of each engine named once; its rules then say nothing more
  var engineOutcome=new HashMap<String,String>();
  for(var engine:snapshot.engines()) {
   if(Set.of("FAILED","SKIPPED","DISABLED","UNSUPPORTED").contains(Objects.toString(engine.status(),""))){
    // The recorded name is a class name; people know the scanner by its own name
    String scannerName=ScannerIdentity.of(engine.scanner()).name();
    String why="FAILED".equals(engine.status())?failureReasons.get(scannerName):null;
    reasons.add(scannerName+" "+outcome(engine.status())+(why==null||why.isBlank()?"":" ("+why+")")+".");
    engineOutcome.put(Objects.toString(engine.scanner(),""),engine.status());
   }
   else if(!CodeScanExecutionSnapshot.completed(engine.status())||engine.scanner()==null||!engine.identity().isReusable()
     ||snapshot.engines().stream().filter(e->Objects.equals(e.scanner(),engine.scanner())).count()!=1)unknown=true;
  }
  var ruleProblems=new LinkedHashMap<String,List<String>>();
  for(var rule:snapshot.rules()) {
   boolean remote=providers.stream().anyMatch(p->Objects.equals(p.policy(),rule.identity())&&p.status()!=null&&p.status().complete());
   if(remote)continue;
   if(Set.of("FAILED","SKIPPED","DISABLED","UNSUPPORTED").contains(Objects.toString(rule.coverage(),""))){
    // A rule that only shares its scanner's outcome adds nothing to the scanner's own line
    if(Objects.equals(engineOutcome.get(Objects.toString(rule.scanner(),"")),rule.coverage()))continue;
    ruleProblems.computeIfAbsent(rule.coverage(),k->new ArrayList<>()).add(rule.name());
   }
   else if(rule.identity()==null||rule.identity().revision()==null||rule.scanner()==null||snapshot.engines().stream().noneMatch(e->rule.scanner().equals(e.scanner())))unknown=true;
  }
  ruleProblems.forEach((coverage,names)->reasons.addAll(ruleReasons(coverage,names)));
  if(!reasons.isEmpty())return new ScanAssessment(processing,"INCOMPLETE",List.copyOf(reasons));
  return new ScanAssessment(processing,unknown?"UNKNOWN":"COMPLETE",unknown?List.of("Which scanners and rules ran could not be fully confirmed."):List.of());
 }
 static final int RULES_LISTED=3;
 /** One line per rule while there are few; past that, a count and the first few names, so a scanner's whole ruleset does not fill the page. */
 static List<String> ruleReasons(String coverage,List<String> names) {
  if(names.size()<=RULES_LISTED)return names.stream().map(n->n+" "+outcome(coverage)+".").toList();
  String listed=String.join(", ",names.subList(0,RULES_LISTED));
  return List.of(names.size()+" rules "+outcomePlural(coverage)+", including "+listed+" and "+(names.size()-RULES_LISTED)+" more.");
 }
 static String outcomePlural(String code) {
  return switch(Objects.toString(code,"")) {
   case "FAILED" -> "failed";
   case "SKIPPED" -> "were skipped";
   case "DISABLED" -> "are turned off";
   case "UNSUPPORTED" -> "could not be checked";
   default -> "did not run";
  };
 }
 /** Plain words for a recorded scanner or rule outcome (UAT walkthrough: no internal codes). */
 static String outcome(String code) {
  return switch(Objects.toString(code,"")) {
   case "FAILED" -> "failed";
   case "SKIPPED" -> "was skipped";
   case "DISABLED" -> "is turned off";
   case "UNSUPPORTED" -> "could not be checked";
   default -> "did not run";
  };
 }
 public static ScanAssessment from(RepoScanReport report) {
  return from(report,report.providerAssessments());
 }
 public static ScanAssessment from(RepoScanReport report,List<ProviderAssessmentReference> providers) {
  var assessment=of(null,report.executionSnapshot(),providers);
  return report.scannerErrors().isEmpty()?assessment:new ScanAssessment("UNKNOWN","INCOMPLETE",report.scannerErrors());
 }
 public static ScanAssessment from(RepoScanEntity scan) {
  return decode(scan.getStatus(),scan.getExecutionSnapshotJson(),scan.getProviderSummaryJson(),scan.getScannerExecutionsJson());
 }
 public static ScanAssessment from(AbstractScanEntity<?,?> scan) {
  if(scan instanceof PullRequestScanEntity pr)return decode(scan.getStatus(),pr.getExecutionSnapshotJson(),pr.getProviderSummaryJson(),pr.getScannerExecutionsJson());
  if(scan instanceof UploadScanEntity upload)return decode(scan.getStatus(),upload.getExecutionSnapshotJson(),null,upload.getScannerExecutionsJson());
  return of(scan.getStatus(),null,List.of());
 }
 /** Why each failed scanner failed, from the scan's recorded executions, by display name. */
 static Map<String,String> failureReasons(String executionsJson) {
  return failureReasons(ScanExecutionSummaryCodec.decode(executionsJson));
 }
 public static Map<String,String> failureReasons(List<ScanExecutionSummary.ScannerExecution> executions) {
  var reasons=new HashMap<String,String>();
  for(var execution:executions)
   if("FAILED".equals(execution.status())&&execution.reason()!=null&&!execution.reason().isBlank())reasons.put(ScannerIdentity.of(execution.scannerName()).name(),execution.reason());
  return reasons;
 }
 private static ScanAssessment decode(ScanStatus status,String json,String providerJson,String executionsJson) {
  try {
   var snapshot=CodeScanExecutionSnapshotCodec.decode(json);
   var executions=ScanExecutionSummaryCodec.decode(executionsJson);
   if(snapshot==null&&!executions.isEmpty())return ofExecutions(status,executions,ProviderAssessmentReference.decode(providerJson));
   return of(status,snapshot,ProviderAssessmentReference.decode(providerJson),failureReasons(executions));
  }
  catch(IllegalArgumentException | NullPointerException malformed){return new ScanAssessment(processing(status),"UNKNOWN",List.of("Stored execution metadata is unreadable."));}
 }
}

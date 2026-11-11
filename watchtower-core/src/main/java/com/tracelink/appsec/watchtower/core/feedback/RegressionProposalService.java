package com.tracelink.appsec.watchtower.core.feedback;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.persistence.MissedVulnerabilityCaseEntity;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateService;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/**
 * Step 1 of R5.3: turns a recorded missed vulnerability into a proposed regression test by comparing
 * the affected file at the vulnerable and fixed commits. Deterministic and stored nowhere; only the
 * reviewer's explicit "save" creates R3 fixture records (references and hashes, never file content).
 */
@Service
public class RegressionProposalService {
 static final int MAX_FILE_BYTES=64*1024,EXCERPT_RADIUS=5,MAX_LINE_CHARS=240;
 private final MissedVulnerabilityService cases;private final AssistantSourceTools source;
 private final RuleCandidateService candidates;private final AssistantAccess access;
 public RegressionProposalService(MissedVulnerabilityService cases,AssistantSourceTools source,RuleCandidateService candidates,AssistantAccess access){
  this.cases=cases;this.source=source;this.candidates=candidates;this.access=access;
 }
 public Map<String,Object> propose(String caseId,String actor){
  var c=cases.find(caseId,actor);var target=source.target(actor,c.repositoryId);
  String vulnerable=target.api().getFileContentAtCommit(c.repositoryName,c.commitHash,c.affectedPath);
  String fixed=c.fixedCommitHash==null?null:target.api().getFileContentAtCommit(c.repositoryName,c.fixedCommitHash,c.affectedPath);
  Map<String,Object> p=new LinkedHashMap<>();
  p.put("case_id",c.caseId);p.put("repository",c.repositoryName);p.put("path",c.affectedPath);p.put("line",c.firstLine);p.put("cwe",c.cwe);
  p.put("vulnerable_commit",c.commitHash);p.put("fixed_commit",c.fixedCommitHash);
  if(vulnerable==null)return status(p,"FILE_UNAVAILABLE","The affected file could not be read at the vulnerable commit. Check the path and commit on the case.");
  if(bytes(vulnerable)>MAX_FILE_BYTES||fixed!=null&&bytes(fixed)>MAX_FILE_BYTES)
   return status(p,"TOO_LARGE","The file is larger than 64 KiB. Reduce it to the vulnerable function by hand and record that as the fixture.");
  var before=lines(vulnerable);List<Map<String,Object>> fixtures=new ArrayList<>();
  fixtures.add(fixture("MATCH",c,"vulnerable",vulnerable,c.commitHash));
  List<LineDiff.Change> changes=List.of();
  if(c.fixedCommitHash==null)status(p,"NO_FIXED_COMMIT","No fixed commit was recorded, so only the vulnerable version can become a test.");
  // The SCM API returns null for both "deleted" and "unavailable"; say so rather than guessing.
  else if(fixed==null)status(p,"FIXED_FILE_REMOVED","The file could not be read at the fixed commit. Either the fix deleted it or the SCM did not return it; check the fixed commit before saving. Only the vulnerable version can become a test.");
  else {
   changes=LineDiff.changes(before,lines(fixed));
   if(changes.isEmpty())return status(p,"NO_CHANGE","The file is identical at both commits. The fix is in another file; record the case against that file.");
   fixtures.add(fixture("NO_MATCH",c,"fixed",fixed,c.fixedCommitHash));
   status(p,"READY","Compared both commits. The vulnerable version should be flagged and the fixed version should not.");
  }
  final var found=changes;
  p.put("changes",found.stream().map(ch->Map.of("vulnerable_from",ch.oldFrom(),"vulnerable_to",ch.oldTo(),"fixed_from",ch.newFrom(),"fixed_to",ch.newTo())).toList());
  p.put("recorded_line_changed",found.stream().anyMatch(ch->ch.coversOld(c.firstLine)));
  // Redact the whole file first so multi-line keys are masked while line numbers stay aligned.
  p.put("excerpt",excerpt(lines(AssistantText.redactSource(vulnerable)),c.firstLine,found));p.put("fixtures",fixtures);
  return p;
 }
 /** Step 2: records the proposal as reviewed R3 fixtures for one rule. Hashes are recomputed here. */
 public List<String> save(String caseId,long ruleId,String actor){
  access.require(actor,"Rule Modify");var p=propose(caseId,actor);
  if(!Set.of("READY","NO_FIXED_COMMIT","FIXED_FILE_REMOVED").contains(p.get("status")))throw new IllegalArgumentException("This case has no proposal to save");
  // Saving twice is harmless: references already recorded for this rule are kept, not duplicated.
  var existing=candidates.fixtures(ruleId).stream().map(f->String.valueOf(f.get("fixture_ref"))).collect(java.util.stream.Collectors.toSet());
  List<String> ids=new ArrayList<>();
  for(var f:fixtures(p))if(!existing.contains(f.get("reference")))ids.add(candidates.fixture(new RuleCandidateService.Fixture(ruleId,(String)f.get("reference"),(String)f.get("sha256"),(String)f.get("expected"),"REGRESSION","missed-case/"+caseId),actor));
  return ids;
 }
 @SuppressWarnings("unchecked") private static List<Map<String,Object>> fixtures(Map<String,Object> p){return (List<Map<String,Object>>)p.get("fixtures");}
 private static Map<String,Object> status(Map<String,Object> p,String status,String explanation){p.put("status",status);p.put("explanation",explanation);return p;}
 private static Map<String,Object> fixture(String expected,MissedVulnerabilityCaseEntity c,String side,String content,String commit){
  String name=c.affectedPath.substring(c.affectedPath.lastIndexOf('/')+1);
  Map<String,Object> f=new LinkedHashMap<>();f.put("expected",expected);f.put("reference","missed/"+c.caseId+"/"+side+"-"+name);
  f.put("sha256",RuleDefinitionHistory.hash(content));f.put("bytes",bytes(content));f.put("commit",commit);return f;
 }
 /** Up to eleven redacted lines around the recorded line, marking lines the fix changed. */
 private static List<Map<String,Object>> excerpt(List<String> lines,int line,List<LineDiff.Change> changes){
  List<Map<String,Object>> excerpt=new ArrayList<>();
  for(int n=Math.max(1,line-EXCERPT_RADIUS);n<=Math.min(lines.size(),line+EXCERPT_RADIUS);n++){
   final int current=n;String text=lines.get(n-1);if(text.length()>MAX_LINE_CHARS)text=text.substring(0,MAX_LINE_CHARS)+"…";
   excerpt.add(Map.of("line",n,"text",text,"changed",changes.stream().anyMatch(ch->ch.coversOld(current)),"recorded",n==line));
  }
  return excerpt;
 }
 private static List<String> lines(String content){return Arrays.asList(content.split("\r?\n",-1));}
 private static int bytes(String content){return content.getBytes(StandardCharsets.UTF_8).length;}
}

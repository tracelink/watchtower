package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSecretFindings;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAssessmentEntity;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAssessmentRepository;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingLocator;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * The card for a finding page. A finding of a secret rule, a finding on a line where a secret was
 * recorded, or a finding whose secret check cannot finish gives only the blocked card: no path, line,
 * rule name or reason. Everything else is rebuilt from the scan, never from what the page says.
 */
@Component
public class FindingContextProvider implements ContextProvider {
 static final Set<String> SCAN_TYPES=Set.of("pull_request","repository");
 static final int MAX_MESSAGE=200;
 private final FindingLocator locator;private final RuleService rules;private final AssistantSecretFindings secrets;
 private final LedgerRepository records;private final FindingAssessmentRepository assessments;
 public FindingContextProvider(FindingLocator locator,RuleService rules,AssistantSecretFindings secrets,LedgerRepository records,FindingAssessmentRepository assessments){
  this.locator=locator;this.rules=rules;this.secrets=secrets;this.records=records;this.assessments=assessments;
 }
 @Override public String kind(){return "finding";}
 @Override public Set<String> grants(){return Set.of("Scan Results View");}

 @Override public ContextCard resolve(ContextRequest.Ids ids){
  if(ids.scanType()==null||!SCAN_TYPES.contains(ids.scanType())||ids.scanId()==null||ids.scanId()<1||ids.findingKey()==null)return ContextCard.unavailable(kind());
  var idMap=ContextService.idMap(new ContextRequest.Ids(ids.scanType(),ids.scanId(),ids.findingKey(),null,null));
  FindingLocator.Detail detail;
  try{detail=locator.locateDetailed(ids.scanType(),ids.scanId(),ids.findingKey());}
  catch(RuntimeException e){return ContextCard.unavailable(kind());}
  var located=detail.located();
  boolean locationChecked;
  try{
   var secret=secrets.secretRules();
   // A finding whose rule is not known at all (an expired report, a legacy row) cannot be told apart from a secret.
   if(located.ruleId()==null&&detail.ruleName()==null)return ContextCard.blocked(kind(),idMap);
   if(isSecretFinding(detail,secret))return ContextCard.blocked(kind(),idMap);
   locationChecked=located.unavailable()==null;
   if(locationChecked&&onSecretLine(detail))return ContextCard.blocked(kind(),idMap);
  }catch(RuntimeException e){
   // Anything that stops the secret check from finishing blocks the finding rather than guessing.
   return ContextCard.blocked(kind(),idMap);
  }
  return card(detail,idMap,locationChecked);
 }
 private boolean isSecretFinding(FindingLocator.Detail detail,AssistantSecretFindings.SecretRules secret){
  var located=detail.located();
  if(located.sensitive())return true;
  RuleDto rule=null;
  if(located.ruleId()!=null){try{rule=rules.getRule(located.ruleId()).toDto();}catch(Exception e){rule=null;}}
  if(rule!=null&&secrets.isSecretRule(rule))return true;
  return secret.contains(located.ruleId(),detail.module(),detail.ruleName());
 }
 /**
  * Whether a secret of any engine was recorded on this finding's line. A pull request finding asks the
  * database about that one line under the spellings of the repository name it knows; a repository-scan
  * finding reads every recorded secret line of the repository, as source reads do.
  */
 private boolean onSecretLine(FindingLocator.Detail detail){
  var located=detail.located();
  if("repository".equals(located.scanType()))return secrets.lines(located.repository()).engine(located.path(),located.line())!=null;
  return secrets.isRecordedSecretLine(located.repository(),located.path(),located.line(),repoNames(detail));
 }
 private static List<String> repoNames(FindingLocator.Detail detail){
  var names=new ArrayList<String>();
  if(detail.located().repository()!=null)names.add(detail.located().repository().getRepoName());
  if(detail.scmRepoName()!=null)names.add(detail.scmRepoName());
  return names;
 }
 /** Path, line and the scanner's message are only included when the line was checked for secrets. */
 private ContextCard card(FindingLocator.Detail detail,Map<String,Object> idMap,boolean locationChecked){
  var located=detail.located();var facts=new LinkedHashMap<String,Object>();
  var rule=new LinkedHashMap<String,Object>();
  if(located.ruleId()!=null)rule.put("id",located.ruleId());
  if(detail.ruleName()!=null)rule.put("name",detail.ruleName());
  if(located.revision()!=null)rule.put("revision",located.revision());
  facts.put("rule",rule);
  if(detail.severity()!=null)facts.put("severity",detail.severity());
  if(located.repository()!=null)facts.put("repository",located.repository().getRepoName());
  if(locationChecked){
   facts.put("path",located.path());facts.put("line",located.line());
   if(detail.message()!=null){String m=AssistantText.redact(detail.message());facts.put("message_untrusted",m.length()>MAX_MESSAGE?m.substring(0,MAX_MESSAGE):m);}
  }
  var judged=records.find(FindingFeedbackEntity.class,located.occurrenceKey());
  facts.put("judgment",judged==null?"NONE":judged.judgment);
  facts.put("assessment_available",assessments.findFirstByOccurrenceKeyOrderByCreatedAtDesc(located.occurrenceKey()).filter(a->FindingAssessmentEntity.ASSESSED.equals(a.getStatus())).isPresent());
  String where=locationChecked?" · "+located.path()+":"+located.line():"";
  return ContextCard.ok(kind(),"Finding · "+(detail.ruleName()==null?"unnamed rule":detail.ruleName())+where,facts,idMap);
 }
}

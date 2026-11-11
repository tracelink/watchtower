package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService;

/**
 * Gathers the bounded evidence for one R6 assessment, or a plain reason why none can be sent. Secret
 * rules, recorded secret lines, uploads and unavailable source are refused before anything leaves.
 */
@Component
public class AssessmentEvidence {
 static final int RADIUS=40,MAX_DEFINITION_CHARS=6000,MIN_JUDGMENTS=5;
 private static final Map<String,String> LANGUAGES=Map.ofEntries(Map.entry("java","java"),Map.entry("kt","kotlin"),Map.entry("py","python"),
  Map.entry("js","javascript"),Map.entry("jsx","javascript"),Map.entry("ts","typescript"),Map.entry("tsx","typescript"),Map.entry("go","go"),
  Map.entry("rb","ruby"),Map.entry("cs","csharp"),Map.entry("php","php"),Map.entry("scala","scala"),Map.entry("yaml","yaml"),Map.entry("yml","yaml"),Map.entry("json","json"));
 /** Either {@code refusal} is set, or the input and its bounds are. {@code secret} says the refusal is because a secret is involved, not just because the evidence is missing. */
 public record Gathered(FindingLocator.Located located,String refusal,String input,int firstLine,int lastLine,Set<String> knowledgeIds,boolean secret) {
  public Gathered(FindingLocator.Located located,String refusal,String input,int firstLine,int lastLine,Set<String> knowledgeIds){this(located,refusal,input,firstLine,lastLine,knowledgeIds,false);}
  static Gathered refused(FindingLocator.Located located,String reason){return new Gathered(located,reason,null,0,0,Set.of(),false);}
  static Gathered refusedSecret(FindingLocator.Located located,String reason){return new Gathered(located,reason,null,0,0,Set.of(),true);}
 }
 private final FindingLocator locator;private final AssistantSourceTools source;private final AssistantSecretFindings secrets;private final AssistantToolRegistry tools;
 private final KnowledgeService knowledge;private final RuleService rules;private final LedgerRepository records;
 public AssessmentEvidence(FindingLocator locator,AssistantSourceTools source,AssistantSecretFindings secrets,AssistantToolRegistry tools,KnowledgeService knowledge,RuleService rules,LedgerRepository records){
  this.locator=locator;this.source=source;this.secrets=secrets;this.tools=tools;this.knowledge=knowledge;this.rules=rules;this.records=records;
 }
 public FindingLocator.Located locate(String scanType,long scanId,String findingKey){return locator.locate(scanType,scanId,findingKey);}
 public Gathered gather(String owner,FindingLocator.Located l){
  if(l.unavailable()!=null)return Gathered.refused(l,l.unavailable());
  RuleDto rule;
  try{rule=rules.getRule(l.ruleId()).toDto();}catch(Exception e){return Gathered.refused(l,"The rule that produced this finding no longer exists.");}
  if(l.sensitive()||secrets.isSecretRule(rule))return Gathered.refusedSecret(l,"This rule detects secrets. Findings of secret rules are never sent to the AI.");
  if(!l.commit().matches("[a-f0-9]{40}")){
   try{l=l.withCommit(source.target(owner,l.repository().getId()).api().fullCommit(l.repository().getRepoName(),l.commit()).toLowerCase(Locale.ROOT));}
   catch(java.io.IOException|RuntimeException e){return Gathered.refused(l,"The scanned commit could not be completed to a full hash by the source control system, so its source cannot be read.");}
  }
  AssistantSourceTools.Window window;
  try{window=source.window(owner,l.repository(),l.commit(),l.path(),l.line(),RADIUS);}
  catch(IllegalArgumentException e){return Gathered.refused(l,"The source at the scanned commit could not be read or checked for secrets: "+e.getMessage());}
  if(window.targetLineMasked())return Gathered.refusedSecret(l,"A secret was recorded on this line, so it is never sent to the AI.");
  String language=language(l.path());
  List<Map<String,Object>> entries=language==null?List.of():knowledge.applicable(rule.getId(),rule.getStewardship()==null?null:rule.getStewardship().getCwe(),l.repository().getId(),language);
  Map<String,Object> input=new LinkedHashMap<>();
  input.put("rule",definition(rule));
  input.put("finding",Map.of("path",l.path(),"line",l.line(),"commit",l.commit(),"language",language==null?"unknown":language));
  input.put("code_window",window.lines());
  input.put("approved_knowledge",entries);
  input.put("earlier_human_judgments_on_rule",judgments(rule.getId(),l.occurrenceKey()));
  int last=window.lines().isEmpty()?l.line():((Number)window.lines().getLast().get("line")).intValue();
  Set<String> ids=new LinkedHashSet<>();entries.forEach(e->ids.add(String.valueOf(e.get("id"))));
  try{return new Gathered(l,null,AssistantState.mapper().writeValueAsString(AssistantToolRegistry.redact(AssistantState.mapper().valueToTree(input))),window.first(),last,Set.copyOf(ids));}
  catch(JsonProcessingException e){throw new IllegalStateException("Assessment input could not be written",e);}
 }
 /** The rule as chat sees it, bounded; an oversized definition is reduced to its summary. */
 private Map<String,Object> definition(RuleDto rule){
  var full=tools.ruleEvidence(rule);
  try{if(AssistantState.mapper().writeValueAsString(full).length()<=MAX_DEFINITION_CHARS)return full;}catch(JsonProcessingException e){/* fall through to the summary */}
  Map<String,Object> summary=new LinkedHashMap<>(full);summary.remove("definition");summary.put("definition_note","The full definition is too large to include.");return summary;
 }
 /**
  * Counts on other findings of the rule only, so the answer cannot echo this finding's own human
  * judgment; below a handful of records the counts could still identify it and are left out.
  */
 private Map<String,Object> judgments(Long ruleId,String occurrenceKey){
  Map<String,Long> counts=new TreeMap<>();long total=0;
  for(var row:records.maps("SELECT f.judgment AS judgment,COUNT(f) AS n FROM FindingFeedbackEntity f WHERE f.ruleId=?1 AND f.occurrenceKey<>?2 GROUP BY f.judgment",0,10,ruleId,occurrenceKey)){
   long n=((Number)row.get("n")).longValue();counts.put(String.valueOf(row.get("judgment")),n);total+=n;
  }
  if(total<MIN_JUDGMENTS)return Map.of("note","Fewer than "+MIN_JUDGMENTS+" other findings of this rule have been judged.");
  return Map.copyOf(counts);
 }
 static String language(String path){
  int dot=path.lastIndexOf('.');return dot<0?null:LANGUAGES.get(path.substring(dot+1).toLowerCase(Locale.ROOT));
 }
}

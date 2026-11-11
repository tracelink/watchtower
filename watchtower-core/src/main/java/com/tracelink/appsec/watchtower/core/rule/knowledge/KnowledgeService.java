package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.time.Clock;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Pattern;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * Reviewed, scoped organization knowledge (plan R5.5). Anyone with Rule Modify proposes; a
 * different person approves. Only approved, current entries inside their language, library,
 * repository, rule and CWE scope are given to the assistant, which can never write them. Entries
 * are evidence for people and the assistant; they never suppress findings or change enforcement.
 */
@Service
public class KnowledgeService {
 private static final Logger LOG=LoggerFactory.getLogger(KnowledgeService.class);
 public static final String PROPOSED="PROPOSED",APPROVED="APPROVED",REJECTED="REJECTED",RETIRED="RETIRED";
 public static final Set<String> KINDS=Set.of("SANITIZER","SOURCE","SINK","FRAMEWORK_GUARANTEE","NOTE");
 static final Set<String> EVIDENCE_TYPES=Set.of("review","finding_feedback","missed_case");
 static final int MAX_REPOSITORIES=50,MAX_RULES=50,MAX_CWES=20,MAX_EVIDENCE=20,MAX_APPLICABLE=20,MAX_CANDIDATES=2000,PAGE=20;
 static final int DEFAULT_REVIEW_MONTHS=12,MAX_REVIEW_MONTHS=24;
 private static final Pattern LANGUAGE=Pattern.compile("[a-z0-9+#._-]{1,32}");
 private static final Pattern VERSION_RANGE=Pattern.compile("[0-9xX*.,<>=~^ -]{1,64}");
 private static final Pattern LIBRARY=Pattern.compile("[\\p{L}\\p{N} .:/@()_+#-]{1,128}");
 private static final Pattern JWT=Pattern.compile("[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}");
 private static final Pattern CWE=Pattern.compile("CWE-[1-9][0-9]{0,8}");
 private static final Pattern WHITESPACE=Pattern.compile("\\s+");
 private static final ObjectMapper MAPPER=new ObjectMapper();
 public record Evidence(String type,String id) { }
 public record Proposal(String kind,String statement,String language,String library,String versionRange,boolean allRepositories,
   List<Long> repositoryIds,List<Long> ruleIds,List<String> cwes,List<Evidence> evidence,String reviewBy) { }
 private final KnowledgeRepository entries;private final KnowledgeAuditRepository audits;private final LedgerRepository records;
 private final RepositoryRepository repositories;private final RuleService rules;private final Clock clock;
 @Autowired
 public KnowledgeService(KnowledgeRepository entries,KnowledgeAuditRepository audits,LedgerRepository records,RepositoryRepository repositories,RuleService rules){
  this(entries,audits,records,repositories,rules,Clock.systemUTC());
 }
 public KnowledgeService(KnowledgeRepository entries,KnowledgeAuditRepository audits,LedgerRepository records,RepositoryRepository repositories,RuleService rules,Clock clock){
  this.entries=entries;this.audits=audits;this.records=records;this.repositories=repositories;this.rules=rules;this.clock=clock;
 }

 @Transactional
 public String propose(Proposal p,String actor){
  var content=validate(p);String id=UUID.randomUUID().toString();long now=clock.millis();
  entries.saveAndFlush(new KnowledgeEntity(id,content,actor,now));audits.save(new KnowledgeAuditEntity(id,"PROPOSED",actor,null,now));
  LOG.info("Knowledge entry {} proposed by {}",id,actor);return id;
 }
 /** A second person approves a current proposal; the proposer cannot. */
 @Transactional
 public void approve(String id,long version,String actor){
  var entry=current(id,version,PROPOSED);
  if(entry.getProposedBy().equalsIgnoreCase(actor))throw new ResponseStatusException(HttpStatus.FORBIDDEN,"A second person must approve this entry");
  if(LocalDate.parse(entry.getReviewBy()).isBefore(today()))throw new ResponseStatusException(HttpStatus.CONFLICT,"This proposal is past its review date; propose it again");
  decide(entry,APPROVED,actor,null);
 }
 @Transactional
 public void reject(String id,long version,String note,String actor){decide(current(id,version,PROPOSED),REJECTED,actor,note(note,false));}
 @Transactional
 public void retire(String id,long version,String note,String actor){decide(current(id,version,APPROVED),RETIRED,actor,note(note,true));}

 /** One page of entries by status, newest first, with whether this viewer may decide each one. */
 @Transactional(readOnly=true)
 public List<Map<String,Object>> list(String status,int offset,String viewer){
  if(!Set.of(PROPOSED,APPROVED,REJECTED,RETIRED).contains(status))throw new IllegalArgumentException("Unknown status");
  if(offset<0||offset>10000||offset%PAGE!=0)throw new IllegalArgumentException("Invalid page");
  return entries.findByStatusOrderByProposedAtDesc(status,PageRequest.of(offset/PAGE,PAGE)).stream().map(e->{
   var view=view(e);view.put("stale",isStale(e));view.put("can_approve",PROPOSED.equals(e.getStatus())&&!e.getProposedBy().equalsIgnoreCase(viewer));return view;
  }).toList();
 }
 @Transactional(readOnly=true)
 public List<Map<String,Object>> audit(String id){
  return audits.findByKnowledgeIdOrderByAuditIdAsc(id).stream().map(a->{Map<String,Object> m=new LinkedHashMap<>();m.put("action",a.getAction());m.put("actor",a.getActor());m.put("note",a.getNote());m.put("created_at",a.getCreatedAt());return m;}).toList();
 }
 /**
  * Approved, current entries that apply to a rule (by id and CWE) in a language and, when given, a
  * repository. Repository-scoped entries apply only when that repository is named.
  */
 @Transactional(readOnly=true)
 public List<Map<String,Object>> applicable(Long ruleId,String ruleCwe,Long repositoryId,String language){
  String lang=language==null?"":language.strip().toLowerCase(Locale.ROOT);
  if(!LANGUAGE.matcher(lang).matches())throw new IllegalArgumentException("Language required");
  String cwe=ruleCwe==null||ruleCwe.isBlank()?null:RuleReviewReport.normalizeCwe(ruleCwe);
  List<Map<String,Object>> result=new ArrayList<>();
  for(var e:entries.findByStatusAndLanguageIgnoreCaseOrderByProposedAtDesc(APPROVED,lang,PageRequest.of(0,MAX_CANDIDATES))){
   if(isStale(e))continue;
   if(!e.isAllRepositories()&&(repositoryId==null||!longs(e.getRepositoryIds()).contains(repositoryId)))continue;
   var scopedRules=longs(e.getRuleIds());if(!scopedRules.isEmpty()&&(ruleId==null||!scopedRules.contains(ruleId)))continue;
   var scopedCwes=strings(e.getCwes());if(!scopedCwes.isEmpty()&&(cwe==null||!scopedCwes.contains(cwe)))continue;
   result.add(forAssistant(e));if(result.size()>=MAX_APPLICABLE)break;
  }
  return result;
 }

 private KnowledgeEntity current(String id,long version,String expected){
  var entry=entries.findById(id==null?"":id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown knowledge entry"));
  if(entry.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"This entry changed; reload");
  if(!expected.equals(entry.getStatus()))throw new ResponseStatusException(HttpStatus.CONFLICT,"This entry is "+entry.getStatus().toLowerCase(Locale.ROOT));
  return entry;
 }
 private void decide(KnowledgeEntity entry,String status,String actor,String note){
  long now=clock.millis();entry.decide(status,actor,note,now);
  try{entries.saveAndFlush(entry);}
  catch(org.springframework.dao.OptimisticLockingFailureException e){throw new ResponseStatusException(HttpStatus.CONFLICT,"This entry changed; reload");}
  audits.save(new KnowledgeAuditEntity(entry.getKnowledgeId(),status,actor,note,now));
  LOG.info("Knowledge entry {} {} by {}",entry.getKnowledgeId(),status.toLowerCase(Locale.ROOT),actor);
 }
 private static String note(String note,boolean required){
  String n=note==null?"":note.strip();
  if(required&&n.isEmpty())throw new IllegalArgumentException("Give a reason");
  if(n.length()>300||!secretFree(n))throw new IllegalArgumentException("Reason must be at most 300 characters without secret values");
  return n.isEmpty()?null:n;
 }

 private KnowledgeEntity.Content validate(Proposal p){
  if(p==null)throw new IllegalArgumentException("Proposal required");
  String kind=p.kind()==null?"":p.kind().strip().toUpperCase(Locale.ROOT);
  if(!KINDS.contains(kind))throw new IllegalArgumentException("Kind must be sanitizer, source, sink, framework guarantee or note");
  String statement=statement(p.statement());
  String language=p.language()==null?"":p.language().strip().toLowerCase(Locale.ROOT);
  if(!LANGUAGE.matcher(language).matches())throw new IllegalArgumentException("Language is required");
  String library=p.library()==null?"":p.library().strip();
  if(!LIBRARY.matcher(library).matches()||!secretFree(library))throw new IllegalArgumentException("Library or framework is required (at most 128 characters, no secret values)");
  String versions=p.versionRange()==null?"":p.versionRange().strip();
  if(!VERSION_RANGE.matcher(versions).matches()||!secretFree(versions))throw new IllegalArgumentException("Version range is required, for example 1.2.x or >=2.0 <3");
  var repos=distinct(p.repositoryIds());
  if(p.allRepositories()!=repos.isEmpty())throw new IllegalArgumentException("Choose all repositories or name at least one repository, not both");
  if(repos.size()>MAX_REPOSITORIES||repos.stream().anyMatch(id->id==null||!repositories.existsById(id)))throw new IllegalArgumentException("Unknown repository in scope");
  var ruleIds=distinct(p.ruleIds());
  if(ruleIds.size()>MAX_RULES)throw new IllegalArgumentException("Too many rules in scope");
  for(Long ruleId:ruleIds){try{rules.getRule(ruleId);}catch(Exception e){throw new IllegalArgumentException("Unknown rule in scope");}}
  if(p.cwes()!=null&&p.cwes().stream().anyMatch(Objects::isNull))throw new IllegalArgumentException("CWEs must look like CWE-79");
  List<String> cwes=new ArrayList<>(new TreeSet<>((p.cwes()==null?List.<String>of():p.cwes()).stream().map(RuleReviewReport::normalizeCwe).toList()));
  if(cwes.size()>MAX_CWES||cwes.stream().anyMatch(c->!CWE.matcher(c).matches()))throw new IllegalArgumentException("CWEs must look like CWE-79");
  var evidence=evidence(p.evidence(),ruleIds);
  return new KnowledgeEntity.Content(kind,statement,language,library,versions,p.allRepositories(),json(repos),json(ruleIds),json(cwes),json(evidence),reviewBy(p.reviewBy()));
 }
 /**
  * Checks the fields of a drafted proposal the way a real proposal is checked, so a draft that passes here passes
  * there. The language, the library and the versions may still be empty: a person fills in what the evidence does
  * not name, and the proposal itself still requires them.
  *
  * @return the fields in the form a proposal takes: kind in capitals, language in lower case, text trimmed
  * @throws IllegalArgumentException saying which field is wrong
  */
 public static Map<String,String> checkedDraft(String kind,String statement,String language,String library,String versionRange){
  String k=kind==null?"":kind.strip().toUpperCase(Locale.ROOT);
  if(!KINDS.contains(k))throw new IllegalArgumentException("Kind must be sanitizer, source, sink, framework guarantee or note");
  String lang=language==null?"":language.strip().toLowerCase(Locale.ROOT);
  if(!lang.isEmpty()&&!LANGUAGE.matcher(lang).matches())throw new IllegalArgumentException("Language is not usable");
  String lib=library==null?"":library.strip();
  if(!lib.isEmpty()&&(!LIBRARY.matcher(lib).matches()||!secretFree(lib)))throw new IllegalArgumentException("Library is not usable");
  String versions=versionRange==null?"":versionRange.strip();
  if(!versions.isEmpty()&&(!VERSION_RANGE.matcher(versions).matches()||!secretFree(versions)))throw new IllegalArgumentException("Version range is not usable");
  Map<String,String> checked=new LinkedHashMap<>();
  checked.put("kind",k);checked.put("statement",statement(statement));checked.put("language",lang);checked.put("library",lib);checked.put("version_range",versions);
  return checked;
 }
 /** Short prose: no code blocks, no line breaks, no secret-like values. */
 static String statement(String raw){
  String s=raw==null?"":raw.strip();
  if(s.length()<10||s.length()>300)throw new IllegalArgumentException("Statement must be 10 to 300 characters");
  if(s.contains("\n")||s.contains("\r")||s.contains("```")||s.contains("<")||s.contains(">"))throw new IllegalArgumentException("Statement must be one line of prose, not code");
  if(!secretFree(s))throw new IllegalArgumentException("Statement must not contain secret values or tokens");
  return s;
 }
 /**
  * Every free-text field is screened before it can reach the AI: the generic secret patterns, JWT
  * shapes, and words that look like keys rather than names. Plain-word passwords cannot be told
  * apart from prose; the second-person approval is the remaining check for those.
  */
 public static boolean secretFree(String text){
  return AssistantText.redact(text).equals(text)&&!JWT.matcher(text).find()&&Arrays.stream(WHITESPACE.split(text)).noneMatch(KnowledgeService::valueLike);
 }
 /**
  * A key-like word: letters and digits keep alternating (generated keys), or a long word with high
  * character entropy that still mixes them. Names such as CVE-2021-44228, log4j2 or sha256sum switch
  * between letters and digits only once or twice and are allowed.
  */
 static boolean valueLike(String raw){
  String word=raw.replaceAll("^\\p{Punct}+|\\p{Punct}+$","");
  int switches=switches(word);
  if(word.length()>=8&&switches>=3)return true;
  return word.length()>=20&&switches>=2&&entropy(word)>=4.0;
 }
 private static int switches(String word){
  int count=0,previous=0;
  for(char c:word.toCharArray()){int kind=Character.isLetter(c)?1:Character.isDigit(c)?2:0;if(kind==0)continue;if(previous!=0&&kind!=previous)count++;previous=kind;}
  return count;
 }
 private static double entropy(String word){
  Map<Integer,Integer> counts=new HashMap<>();word.chars().forEach(c->counts.merge(c,1,Integer::sum));
  double bits=0;for(int n:counts.values()){double p=(double)n/word.length();bits-=p*Math.log(p)/Math.log(2);}return bits;
 }
 /** When rules are scoped, reviews and judgments must belong to one of them. */
 private List<Evidence> evidence(List<Evidence> raw,List<Long> ruleIds){
  if(raw==null||raw.isEmpty()||raw.size()>MAX_EVIDENCE)throw new IllegalArgumentException("Give 1 to 20 evidence references");
  List<Evidence> result=new ArrayList<>();
  for(var e:raw){
   if(e==null||e.type()==null||!EVIDENCE_TYPES.contains(e.type())||e.id()==null||e.id().isBlank()||e.id().length()>64)throw new IllegalArgumentException("Unknown evidence reference");
   boolean exists=switch(e.type()){
    case "review"->{var review=records.find(RuleReviewItemEntity.class,e.id());yield review!=null&&"ACCEPTED".equals(review.status)&&(ruleIds.isEmpty()||ruleIds.contains(review.ruleId));}
    case "finding_feedback"->{var judgment=records.find(FindingFeedbackEntity.class,e.id());yield judgment!=null&&(ruleIds.isEmpty()||ruleIds.contains(judgment.ruleId));}
    default->records.find(MissedVulnerabilityCaseEntity.class,e.id())!=null;
   };
   if(!exists)throw new IllegalArgumentException("Evidence must be an accepted review, a recorded judgment or a recorded missed case for the scoped rules");
   var ref=new Evidence(e.type(),e.id());if(!result.contains(ref))result.add(ref);
  }
  return result;
 }
 private String reviewBy(String raw){
  LocalDate today=today();
  if(raw==null||raw.isBlank())return today.plusMonths(DEFAULT_REVIEW_MONTHS).toString();
  try{
   var date=LocalDate.parse(raw.strip());
   if(!date.isAfter(today)||date.isAfter(today.plusMonths(MAX_REVIEW_MONTHS)))throw new IllegalArgumentException("Review date must be within the next 24 months");
   return date.toString();
  }catch(DateTimeParseException e){throw new IllegalArgumentException("Review date must look like 2027-10-13");}
 }
 private boolean isStale(KnowledgeEntity e){return LocalDate.parse(e.getReviewBy()).isBefore(today());}
 private LocalDate today(){return LocalDate.now(clock);}
 private static <T> List<T> distinct(List<T> values){return values==null?List.of():List.copyOf(new LinkedHashSet<>(values));}

 private static Map<String,Object> view(KnowledgeEntity e){
  Map<String,Object> v=new LinkedHashMap<>();
  v.put("id",e.getKnowledgeId());v.put("kind",e.getKind());v.put("statement",e.getStatement());v.put("language",e.getLanguage());v.put("library",e.getLibrary());
  v.put("version_range",e.getVersionRange());v.put("all_repositories",e.isAllRepositories());v.put("repository_ids",longs(e.getRepositoryIds()));
  v.put("rule_ids",longs(e.getRuleIds()));v.put("cwes",strings(e.getCwes()));v.put("evidence",evidenceOf(e.getEvidenceJson()));v.put("status",e.getStatus());
  v.put("review_by",e.getReviewBy());v.put("proposed_by",e.getProposedBy());v.put("proposed_at",e.getProposedAt());v.put("decided_by",e.getDecidedBy());
  v.put("decided_at",e.getDecidedAt());v.put("decision_note",e.getDecisionNote());v.put("version",e.getVersion());return v;
 }
 /** What the assistant receives: content, scope, evidence and dates, without people's names. */
 private static Map<String,Object> forAssistant(KnowledgeEntity e){
  var v=view(e);for(String key:List.of("proposed_by","proposed_at","decided_by","decision_note","version","status"))v.remove(key);v.put("approved_at",e.getDecidedAt());return v;
 }
 private static String json(Object value){try{return MAPPER.writeValueAsString(value);}catch(JsonProcessingException e){throw new IllegalStateException("Knowledge scope could not be written",e);}}
 static List<Long> longs(String json){try{return MAPPER.readValue(json,new TypeReference<List<Long>>(){});}catch(JsonProcessingException e){throw new IllegalStateException("Stored knowledge scope unreadable",e);}}
 static List<String> strings(String json){try{return MAPPER.readValue(json,new TypeReference<List<String>>(){});}catch(JsonProcessingException e){throw new IllegalStateException("Stored knowledge scope unreadable",e);}}
 static List<Evidence> evidenceOf(String json){try{return MAPPER.readValue(json,new TypeReference<List<Evidence>>(){});}catch(JsonProcessingException e){throw new IllegalStateException("Stored knowledge evidence unreadable",e);}}
}

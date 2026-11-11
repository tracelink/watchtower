package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiProvider;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * Advisory AI assessment of one finding, on request (plan R6). Its own switch; charged to the
 * requester's and the organization's daily chat budgets. Answers are stored apart from human
 * judgments, never change findings or health, and record who saw them first so agreement with human
 * judgments counts only blind cases.
 */
@Service
public class FindingAssessmentService {
 private static final Logger LOG=LoggerFactory.getLogger(FindingAssessmentService.class);
 static final String SAFETY_ID="watchtower-finding-assessment";
 static final int AGREEMENT_ROWS=5000,CHUNK=500;
 /** The provider call; production uses the approved OpenAI Responses endpoint. */
 @FunctionalInterface public interface Provider { OpenAiLlmClient.StructuredReply assess(OpenAiLlmClient.Structured request)throws IOException,InterruptedException; }
 private final AssessmentEvidence evidence;private final FindingAssessmentRepository assessments;private final FindingAssessmentViewRepository views;private final FindingAiExposures exposures;
 private final AssistantSettingsService settings;private final AiIntegrationService integrations;private final AssistantAccess access;
 private final AssistantBudgetService budgets;private final LedgerRepository records;private final TransactionTemplate tx;private final Provider provider;private final Clock clock;
 /** The collaborators that are not storage. */
 public record Services(AssessmentEvidence evidence,AssistantSettingsService settings,AiIntegrationService integrations,AssistantAccess access,AssistantBudgetService budgets) { }
 @Autowired
 public FindingAssessmentService(AssessmentEvidence evidence,FindingAssessmentRepository assessments,FindingAssessmentViewRepository views,FindingAiExposures exposures,AssistantSettingsService settings,
   AiIntegrationService integrations,AssistantAccess access,AssistantBudgetService budgets,LedgerRepository records,PlatformTransactionManager tm,OpenAiLlmClient client){
  this(new Services(evidence,settings,integrations,access,budgets),assessments,views,exposures,records,tm,client::structured,Clock.systemUTC());
 }
 public FindingAssessmentService(Services s,FindingAssessmentRepository assessments,FindingAssessmentViewRepository views,FindingAiExposures exposures,LedgerRepository records,PlatformTransactionManager tm,Provider provider,Clock clock){
  this.evidence=s.evidence();this.settings=s.settings();this.integrations=s.integrations();this.access=s.access();this.budgets=s.budgets();
  this.assessments=assessments;this.views=views;this.exposures=exposures;this.records=records;this.tx=new TransactionTemplate(tm);this.provider=provider;this.clock=clock;
 }

 /** Whether assessments can be requested now, and if not, why. */
 public record Readiness(String problem,String message) { }
 public Readiness readiness(){
  var cfg=settings.get().settings();
  if(!cfg.findingAssessment().enabled())return new Readiness("OFF","AI finding assessment is off. An Assistant Admin can turn it on in Assistant settings.");
  var key=integrations.view(AiProvider.OPENAI);
  if(!key.configured())return new Readiness("NO_API_KEY","No OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.");
  if(Boolean.FALSE.equals(key.healthOk())&&"PROVIDER_AUTHENTICATION".equals(key.healthError()))return new Readiness("API_KEY_REJECTED","OpenAI rejected the configured API key. An Assistant Admin can test or replace it.");
  try{cfg.model(cfg.defaultModel(),cfg.defaultEffort());}catch(IllegalArgumentException e){return new Readiness("MODEL_UNAVAILABLE","Choose an allowed default model in Assistant settings.");}
  return new Readiness(null,"Advisory only: a person makes the judgment, and nothing about the finding changes.");
 }

 /** The stored answer for this finding (recording that the viewer saw it), or the request state. */
 public Map<String,Object> latest(String owner,String scanType,long scanId,String findingKey){
  requireAccess(owner);
  var located=evidence.locate(scanType,scanId,findingKey);
  var stored=assessments.findFirstByOccurrenceKeyOrderByCreatedAtDesc(located.occurrenceKey());
  if(stored.isPresent())return seen(stored.get(),owner);
  var state=readiness();return status(state.problem()==null?"NONE":state.problem(),state.message());
 }
 public Map<String,Object> assess(String owner,String scanType,long scanId,String findingKey){return assessWith(owner,scanType,scanId,findingKey,null);}
 /** Batch triage: the same assessment, under its own switch (checked by the caller) and charged to its own daily share. */
 public Map<String,Object> assessForBatch(String owner,String scanType,long scanId,String findingKey){return assessWith(owner,scanType,scanId,findingKey,AssistantFeature.BATCH_TRIAGE);}
 private Map<String,Object> assessWith(String owner,String scanType,long scanId,String findingKey,AssistantFeature share){
  requireAccess(owner);
  var state=share==null?readiness():new Readiness(null,"");if(state.problem()!=null)return status(state.problem(),state.message());
  var cfg=settings.get().settings();var model=cfg.model(cfg.defaultModel(),cfg.defaultEffort());
  var located=evidence.locate(scanType,scanId,findingKey);
  var cached=assessments.findByOccurrenceKeyAndModelAndEffortAndPromptVersion(located.occurrenceKey(),model.id(),cfg.defaultEffort(),AssessmentText.PROMPT_VERSION);
  if(cached.isPresent()&&FindingAssessmentEntity.ASSESSED.equals(cached.get().getStatus()))return seen(cached.get(),owner);
  // A rejected answer is replaced when someone asks again; the daily budgets bound the cost.
  cached.ifPresent(rejected->tx.executeWithoutResult(s->assessments.deleteById(rejected.getAssessmentId())));
  // Checked before any source download, so an exhausted budget cannot trigger repository fetches.
  var budgetFeature=share==null?AssistantFeature.FINDING_ASSESSMENT:share;
  if(!budgets.canAfford(owner,cfg,model,AssistantSettings.FindingAssessment.INPUT_TOKENS,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,budgetFeature))
   throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(budgetFeature,budgets.shortfall(owner,cfg,model,AssistantSettings.FindingAssessment.INPUT_TOKENS,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,budgetFeature)));
  var gathered=evidence.gather(owner,located);
  if(gathered.refusal()!=null){var refused=status("INSUFFICIENT_EVIDENCE",gathered.refusal());if(gathered.secret())refused.put("blocked","secret");return refused;}
  String schema=AssessmentText.schema().toString();
  long inputBound=(long)(AssessmentText.INSTRUCTIONS+gathered.input()+schema).getBytes(StandardCharsets.UTF_8).length+256;
  if(inputBound>AssistantSettings.FindingAssessment.INPUT_TOKENS)return status("INSUFFICIENT_EVIDENCE","The evidence for this finding is too large to send.");
  AssistantBudgetService.Charge charge;
  try{charge=budgets.reserveDirect(owner,cfg,model,inputBound,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,share==null?AssistantFeature.FINDING_ASSESSMENT:share);}
  catch(IllegalStateException e){throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(budgetFeature,budgets.shortfall(owner,cfg,model,inputBound,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,budgetFeature)));}
  OpenAiLlmClient.StructuredReply reply;
  try{
   reply=provider.assess(new OpenAiLlmClient.Structured(model.id(),cfg.defaultEffort(),AssessmentText.INSTRUCTIONS,gathered.input(),"finding_assessment",AssessmentText.schema(),
     AssistantSettings.FindingAssessment.OUTPUT_TOKENS,cfg.providerTimeoutSeconds(),SAFETY_ID));
  }catch(LlmClient.ProviderFailure e){
   // An error reply used nothing; a transport failure may have been charged, so it stays reserved.
   if(!"PROVIDER_TRANSPORT".equals(e.code()))budgets.settleDirect(charge,0,0);
   LOG.warn("Finding assessment failed for {}: {}",owner,e.code());
   throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OpenAI could not answer right now; try again later.");
  }catch(IOException|RuntimeException e){LOG.warn("Finding assessment failed for {}: provider unavailable",owner);throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OpenAI could not answer right now; try again later.");}
  catch(InterruptedException e){Thread.currentThread().interrupt();throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Interrupted");}
  long tokens=reply.inputTokens()+reply.outputTokens();
  long actual=reply.usageKnown()&&tokens<=charge.tokens()?Math.min(charge.cost(),model.cost(reply.inputTokens(),reply.outputTokens())):charge.cost();
  if(actual<charge.cost())budgets.settleDirect(charge,Math.min(tokens,charge.tokens()),actual);
  var answer=reply.refused()||!"completed".equals(reply.status())?Optional.<AssessmentText.Answer>empty():parse(reply.text(),gathered);
  var subject=new FindingAssessmentEntity.Subject(located.occurrenceKey(),located.scanType(),located.scanId(),located.findingKey(),located.ruleId(),located.revision(),
    model.id(),cfg.defaultEffort(),AssessmentText.PROMPT_VERSION,owner);
  var stored=answer.map(a->new FindingAssessmentEntity.Answer(FindingAssessmentEntity.ASSESSED,a.verdict(),json(a.criteria()),json(a.citedLines()),json(a.knowledgeIds()),reply.inputTokens(),reply.outputTokens(),actual))
    .orElseGet(()->new FindingAssessmentEntity.Answer(FindingAssessmentEntity.REJECTED,null,null,null,null,reply.inputTokens(),reply.outputTokens(),actual));
  var entity=new FindingAssessmentEntity(UUID.randomUUID().toString(),subject,stored,clock.millis());
  try{tx.executeWithoutResult(s->assessments.saveAndFlush(entity));}
  catch(DataIntegrityViolationException e){
   // Another person asked at the same moment; theirs is the stored answer.
   return seen(assessments.findByOccurrenceKeyAndModelAndEffortAndPromptVersion(located.occurrenceKey(),model.id(),cfg.defaultEffort(),AssessmentText.PROMPT_VERSION).orElseThrow(()->e),owner);
  }
  LOG.info("Finding assessment {} ({}) stored for {} by {}",entity.getAssessmentId(),entity.getStatus(),located.occurrenceKey(),owner);
  return seen(entity,owner);
 }

 /**
  * Agreement of likely true/false positive verdicts with human judgments, counting only blind cases:
  * the person who judged had not seen the assessment before their latest judgment.
  */
 public Map<String,Object> agreement(){
  var rows=assessments.findByStatusOrderByCreatedAtDesc(FindingAssessmentEntity.ASSESSED,PageRequest.of(0,AGREEMENT_ROWS));
  Map<String,FindingFeedbackEntity> judgments=new HashMap<>();Map<String,List<FindingAssessmentViewEntity>> seen=new HashMap<>();Map<String,List<FindingAiExposureEntity>> exposed=new HashMap<>();
  var keys=rows.stream().map(FindingAssessmentEntity::getOccurrenceKey).distinct().toList();var ids=rows.stream().map(FindingAssessmentEntity::getAssessmentId).toList();
  for(int i=0;i<keys.size();i+=CHUNK)for(var f:records.list(FindingFeedbackEntity.class,"SELECT f FROM FindingFeedbackEntity f WHERE f.occurrenceKey IN ?1",0,CHUNK,keys.subList(i,Math.min(keys.size(),i+CHUNK))))judgments.put(f.occurrenceKey,f);
  for(int i=0;i<keys.size();i+=CHUNK)for(var x:exposures.forFindings(keys.subList(i,Math.min(keys.size(),i+CHUNK))))exposed.computeIfAbsent(x.getOccurrenceKey(),k->new ArrayList<>()).add(x);
  for(int i=0;i<ids.size();i+=CHUNK)for(var v:views.findByAssessmentIdIn(ids.subList(i,Math.min(ids.size(),i+CHUNK))))seen.computeIfAbsent(v.getAssessmentId(),k->new ArrayList<>()).add(v);
  Map<String,Long> matrix=new TreeMap<>();long notBlind=0,unjudged=0,undecided=0,agree=0,blind=0;Set<String> counted=new HashSet<>();
  for(var a:rows){
   // Newest first: one finding counts once, by its latest answer, whatever model or prompt produced older ones.
   if(!counted.add(a.getOccurrenceKey()))continue;
   if(!Set.of("LIKELY_TRUE_POSITIVE","LIKELY_FALSE_POSITIVE").contains(a.getVerdict())){undecided++;continue;}
   var j=judgments.get(a.getOccurrenceKey());
   if(j==null||!Set.of("TRUE_POSITIVE","FALSE_POSITIVE").contains(j.judgment)){unjudged++;continue;}
   // Seeing the stored assessment, or any AI opinion about this finding in chat, before judging makes the case not blind.
   boolean sawFirst=seen.getOrDefault(a.getAssessmentId(),List.of()).stream().anyMatch(v->v.getViewer().equalsIgnoreCase(j.reviewer)&&v.getFirstViewedAt()<=j.updatedAt)
     ||exposed.getOrDefault(a.getOccurrenceKey(),List.of()).stream().anyMatch(x->x.getViewer().equalsIgnoreCase(j.reviewer)&&x.getFirstSeenAt()<=j.updatedAt);
   if(sawFirst){notBlind++;continue;}
   blind++;matrix.merge(a.getVerdict()+"|"+j.judgment,1L,Long::sum);
   if(a.getVerdict().equals("LIKELY_"+j.judgment))agree++;
  }
  Map<String,Object> result=new LinkedHashMap<>();
  result.put("blind_cases",blind);result.put("agreed",agree);result.put("agreement_rate",blind==0?null:(double)agree/blind);result.put("matrix",matrix);
  result.put("excluded_seen_before_judging",notBlind);result.put("excluded_no_human_judgment",unjudged);result.put("excluded_needs_review_or_insufficient",undecided);
  result.put("assessments_considered",rows.size());
  result.put("note","Counts only judgments made without seeing the assessment. Agreement on reviewed findings is not rule precision, and no routing uses these verdicts.");
  return result;
 }

 private void requireAccess(String owner){
  access.require(owner,"Assistant Use");for(String grant:AssistantSourceTools.GRANTS)access.require(owner,grant);
 }
 private Map<String,Object> seen(FindingAssessmentEntity a,String viewer){
  var key=new FindingAssessmentViewEntity.Key(a.getAssessmentId(),viewer);
  // Only an answer that is shown counts as seen; a rejected one is never displayed.
  if(FindingAssessmentEntity.ASSESSED.equals(a.getStatus()))exposures.record(a.getOccurrenceKey(),viewer,FindingAiExposures.ASSESSMENT);
  if(!views.existsById(key)){
   try{tx.executeWithoutResult(s->views.saveAndFlush(new FindingAssessmentViewEntity(a.getAssessmentId(),viewer,clock.millis())));}
   catch(DataIntegrityViolationException e){/* recorded by a concurrent request of the same viewer */}
  }
  Map<String,Object> v=new LinkedHashMap<>();v.put("state",a.getStatus());v.put("id",a.getAssessmentId());
  if(FindingAssessmentEntity.ASSESSED.equals(a.getStatus())){
   v.put("verdict",a.getVerdict());v.put("criteria",read(a.getCriteriaJson(),new TypeReference<Map<String,Map<String,String>>>(){}));
   v.put("cited_lines",read(a.getCitedLines(),new TypeReference<List<Integer>>(){}));v.put("knowledge_ids",read(a.getKnowledgeIds(),new TypeReference<List<String>>(){}));
  }else v.put("message","The AI answer did not pass validation and is not shown.");
  v.put("model",a.getModel());v.put("rule_revision",a.getRuleRevision());v.put("created_at",a.getCreatedAt());
  v.put("note","Advisory only: a person makes the judgment, and nothing about the finding changes.");
  return v;
 }
 private static Map<String,Object> status(String state,String message){Map<String,Object> v=new LinkedHashMap<>();v.put("state",state);v.put("message",message);return v;}
 private static Optional<AssessmentText.Answer> parse(String text,AssessmentEvidence.Gathered g){
  try{return AssessmentText.accept(AssistantState.mapper().readTree(text),g.firstLine(),g.lastLine(),g.knowledgeIds());}catch(JsonProcessingException|RuntimeException e){return Optional.empty();}
 }
 private static String json(Object value){try{return AssistantState.mapper().writeValueAsString(value);}catch(JsonProcessingException e){throw new IllegalStateException("Assessment could not be written",e);}}
 private static <T> T read(String json,TypeReference<T> type){try{return AssistantState.mapper().readValue(json,type);}catch(JsonProcessingException e){throw new IllegalStateException("Stored assessment unreadable",e);}}
}

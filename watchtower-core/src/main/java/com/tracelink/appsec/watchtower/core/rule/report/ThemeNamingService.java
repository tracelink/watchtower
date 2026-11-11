package com.tracelink.appsec.watchtower.core.rule.report;

import java.io.IOException;
import java.time.*;
import java.time.temporal.TemporalAdjusters;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiProvider;
import com.tracelink.appsec.watchtower.core.persistence.AssistantBudgetDailyEntity;
import com.tracelink.appsec.watchtower.core.persistence.AssistantSettingsEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * AI names for the latest review report's feedback themes (plan R5.2b). Runs on one pod at a
 * time, outside report generation, with its own switch and weekly budget. A theme whose rule
 * detects secrets is named from counts and categories only. Names are suggestions attached when
 * the report is viewed; they never change labels, health, review items or enforcement.
 */
@Service
public class ThemeNamingService {
 private static final Logger LOG=LoggerFactory.getLogger(ThemeNamingService.class);
 static final String BUDGET_SCOPE="rule-review-theme-naming";
 static final int MAX_PER_RUN=25,MAX_RECORDS=10;
 static final long RUN_MILLIS=10*60*1000L,UNUSED_MILLIS=84L*24*60*60*1000;
 static final String SAFETY_ID="watchtower-rule-review-theme-naming";
 private static final Map<String,String> SOURCES=Map.of("finding_feedback","false-positive judgments","bypass","pull request bypasses","review_outcome","rule review decisions");
 /** The provider call; production uses the approved OpenAI Responses endpoint. */
 @FunctionalInterface public interface Provider { OpenAiLlmClient.StructuredReply name(OpenAiLlmClient.Structured request)throws IOException,InterruptedException; }
 enum Outcome { NAMED, REJECTED, BUDGET, FAILED }
 private final RuleReviewReportRepository reports;private final ThemeNameRepository names;private final AssistantSettingsService settings;
 private final AiIntegrationService integrations;private final AssistantSecretFindings secrets;private final LedgerRepository records;
 private final TransactionTemplate tx;private final Provider provider;private final Clock clock;
 @Autowired
 public ThemeNamingService(RuleReviewReportRepository reports,ThemeNameRepository names,AssistantSettingsService settings,AiIntegrationService integrations,
   AssistantSecretFindings secrets,LedgerRepository records,PlatformTransactionManager tm,OpenAiLlmClient client){
  this(reports,names,settings,integrations,secrets,records,tm,client::structured,Clock.systemUTC());
 }
 public ThemeNamingService(RuleReviewReportRepository reports,ThemeNameRepository names,AssistantSettingsService settings,AiIntegrationService integrations,
   AssistantSecretFindings secrets,LedgerRepository records,PlatformTransactionManager tm,Provider provider,Clock clock){
  this.reports=reports;this.names=names;this.settings=settings;this.integrations=integrations;this.secrets=secrets;this.records=records;
  this.tx=new TransactionTemplate(tm);this.provider=provider;this.clock=clock;
 }

 /** Names up to 25 unnamed themes of the latest report in rank order; stops on the first provider failure. */
 @Scheduled(fixedDelay=300_000,initialDelay=120_000)
 @SchedulerLock(name="ruleReviewThemeNaming",lockAtMostFor="PT15M")
 public void scheduled(){
  try{run();}catch(RuntimeException e){LOG.warn("Rule review theme naming failed; retrying on the next run",e);}
 }
 public void run(){
  long started=clock.millis();var state=readiness();
  if(state.problem()!=null)return;
  var latest=reports.findFirstByOrderByCreatedAtDesc();if(latest.isEmpty())return;
  var themes=themes(latest.get());var cfg=state.settings();var naming=cfg.themeNaming();
  var model=cfg.model(naming.model(),naming.effort());var secretRules=secrets.secretRules();
  var fingerprints=themes.stream().map(t->(String)t.get("fingerprint")).toList();
  if(!fingerprints.isEmpty())tx.executeWithoutResult(s->names.touch(fingerprints,started));
  int attempted=0;
  for(var theme:themes){
   if(attempted>=MAX_PER_RUN||clock.millis()-started>RUN_MILLIS)break;
   var request=request(theme,naming,secretRules);
   if(names.existsById(request.nameKey()))continue;
   attempted++;
   var outcome=name(theme,request,cfg,model);
   if(outcome==Outcome.BUDGET||outcome==Outcome.FAILED)break;
  }
  tx.executeWithoutResult(s->names.deleteUnusedBefore(started-UNUSED_MILLIS));
  if(attempted>0)LOG.info("Rule review theme naming attempted {} theme(s) of report {}",attempted,latest.get().getReportId());
 }

 /** Whether naming can run now, and if not, why; the report dialog shows the message. */
 public record Readiness(String problem,String message,AssistantSettings settings) { }
 public Readiness readiness(){
  var cfg=settings.get().settings();var naming=cfg.themeNaming();
  if(!naming.enabled())return new Readiness("OFF","AI theme naming is off. An Assistant Admin can turn it on in Assistant settings.",cfg);
  var key=integrations.view(AiProvider.OPENAI);
  if(!key.configured())return new Readiness("NO_API_KEY","AI theme naming is on, but no OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.",cfg);
  if(Boolean.FALSE.equals(key.healthOk())&&"PROVIDER_AUTHENTICATION".equals(key.healthError()))
   return new Readiness("API_KEY_REJECTED","AI theme naming is paused: OpenAI rejected the configured API key. An Assistant Admin can test or replace it in Assistant settings → AI integration.",cfg);
  try{cfg.model(naming.model(),naming.effort());}
  catch(IllegalArgumentException e){return new Readiness("MODEL_UNAVAILABLE","AI theme naming is paused: its model is no longer allowed. An Assistant Admin can choose another in Assistant settings.",cfg);}
  if(spent(weekStart())+worstCase(cfg)>naming.weeklyCostMicros())
   return new Readiness("BUDGET_USED",String.format(Locale.ROOT,"This week's AI naming budget ($%.2f) is used up; naming resumes on Monday (UTC).",naming.weeklyCostMicros()/1e6),cfg);
  return new Readiness(null,"AI names are suggestions from repeated feedback; they do not change labels or rule health.",cfg);
 }

 /** A copy of the report view with each theme's latest suggestion and the naming status attached. */
 @SuppressWarnings("unchecked")
 public Map<String,Object> attach(Map<String,Object> latest){
  if(!(latest.get("report") instanceof Map<?,?> report)||!(report.get("summary") instanceof Map<?,?> summary)||!(summary.get("themes") instanceof List<?> themes))return latest;
  var fingerprints=themes.stream().map(t->((Map<String,Object>)t).get("fingerprint")).filter(String.class::isInstance).map(String.class::cast).distinct().toList();
  Map<String,ThemeNameEntity> newest=new HashMap<>();
  if(!fingerprints.isEmpty())for(var row:names.findByThemeFingerprintInOrderByCreatedAtDesc(fingerprints))newest.putIfAbsent(row.getThemeFingerprint(),row);
  List<Map<String,Object>> decorated=new ArrayList<>();int named=0;
  for(var item:themes){
   Map<String,Object> theme=new LinkedHashMap<>((Map<String,Object>)item);var row=newest.get(theme.get("fingerprint"));
   if(row!=null){theme.put("ai",view(row));if(ThemeNameEntity.NAMED.equals(row.getStatus()))named++;}
   decorated.add(theme);
  }
  var state=statusForView();Map<String,Object> status=new LinkedHashMap<>();
  status.put("state",state.problem()==null?"ON":state.problem());status.put("message",state.message());status.put("named",named);status.put("themes",themes.size());
  Map<String,Object> newSummary=new LinkedHashMap<>((Map<String,Object>)summary);newSummary.put("themes",decorated);newSummary.put("ai_naming",status);
  Map<String,Object> newReport=new LinkedHashMap<>((Map<String,Object>)report);newReport.put("summary",newSummary);
  Map<String,Object> result=new LinkedHashMap<>(latest);result.put("report",newReport);return result;
 }
 /** The report stays viewable when the naming status cannot be read; the dialog says so. */
 private Readiness statusForView(){
  try{return readiness();}
  catch(RuntimeException e){LOG.warn("AI theme naming status unavailable",e);return new Readiness("UNAVAILABLE","AI theme naming status is unavailable; existing suggestions are still shown.",null);}
 }
 private static Map<String,Object> view(ThemeNameEntity row){
  Map<String,Object> ai=new LinkedHashMap<>();ai.put("status",row.getStatus());
  if(ThemeNameEntity.NAMED.equals(row.getStatus())){ai.put("name",row.getName());ai.put("cause",row.getCause());ai.put("cause_label",ThemeNamingText.CAUSES.get(row.getCause()));ai.put("explanation",row.getExplanation());}
  ai.put("model",row.getModel());ai.put("text_sent",row.isTextSent());ai.put("created_at",row.getCreatedAt());return ai;
 }

 private ThemeNameEntity.Request request(Map<String,Object> theme,AssistantSettings.ThemeNaming naming,AssistantSecretFindings.SecretRules secretRules){
  String fingerprint=(String)theme.get("fingerprint");long ruleId=((Number)theme.get("rule_id")).longValue();
  // A deleted rule cannot be classified, so its records are treated like a secret rule's.
  boolean withhold=secretRules.ids().contains(ruleId)||theme.get("name")==null;
  return new ThemeNameEntity.Request(sha256(fingerprint+"\u0000"+naming.model()+"\u0000"+naming.effort()+"\u0000"+ThemeNamingText.PROMPT_VERSION),fingerprint,ruleId,naming.model(),naming.effort(),ThemeNamingText.PROMPT_VERSION,!withhold);
 }
 private Outcome name(Map<String,Object> theme,ThemeNameEntity.Request planned,AssistantSettings cfg,AssistantSettings.Model model){
  var texts=planned.textSent()?texts(theme):Texts.NONE;
  var request=new ThemeNameEntity.Request(planned.nameKey(),planned.fingerprint(),planned.ruleId(),planned.model(),planned.effort(),planned.promptVersion(),!texts.records().isEmpty());
  String input=input(theme,texts);long reserved=worstCase(cfg);long bucket=weekStart();
  if(!reserve(bucket,reserved,cfg.themeNaming().weeklyCostMicros()))return Outcome.BUDGET;
  OpenAiLlmClient.StructuredReply reply;
  try{
   reply=provider.name(new OpenAiLlmClient.Structured(model.id(),request.effort(),ThemeNamingText.INSTRUCTIONS,input,"feedback_theme_name",ThemeNamingText.schema(),
     AssistantSettings.ThemeNaming.OUTPUT_TOKENS,cfg.providerTimeoutSeconds(),SAFETY_ID));
  }catch(LlmClient.ProviderFailure e){
   // The provider answered with an error: nothing was used. A transport failure may have been charged.
   if(!"PROVIDER_TRANSPORT".equals(e.code()))settle(bucket,reserved,0);
   LOG.warn("Rule review theme naming stopped for this run: {}",e.code());return Outcome.FAILED;
  }catch(IOException|RuntimeException e){LOG.warn("Rule review theme naming stopped for this run: provider unavailable");return Outcome.FAILED;}
  catch(InterruptedException e){Thread.currentThread().interrupt();return Outcome.FAILED;}
  long actual=reply.usageKnown()?Math.min(reserved,model.cost(reply.inputTokens(),reply.outputTokens())):reserved;
  settle(bucket,reserved,actual);
  var suggestion=reply.refused()||!"completed".equals(reply.status())?Optional.<ThemeNamingText.Suggestion>empty():parse(reply.text());
  var outcome=suggestion.map(s->new ThemeNameEntity.Outcome(ThemeNameEntity.NAMED,s.name(),s.cause(),s.explanation(),reply.inputTokens(),reply.outputTokens(),actual))
    .orElseGet(()->new ThemeNameEntity.Outcome(ThemeNameEntity.REJECTED,null,null,null,reply.inputTokens(),reply.outputTokens(),actual));
  tx.executeWithoutResult(s->names.saveAndFlush(new ThemeNameEntity(request,outcome,clock.millis())));
  return suggestion.isPresent()?Outcome.NAMED:Outcome.REJECTED;
 }
 private static Optional<ThemeNamingText.Suggestion> parse(String text){
  try{return ThemeNamingText.accept(AssistantState.mapper().readTree(text));}catch(JsonProcessingException|RuntimeException e){return Optional.empty();}
 }
 /**
  * Redacted record text, and whether every record of the theme was allowed. Shared terms are built
  * from all records, so they are sent only when none was withheld.
  */
 record Texts(List<String> records,boolean complete) { static final Texts NONE=new Texts(List.of(),false); }
 /** Rule, category and counts, plus redacted record text and shared terms when the rule does not detect secrets. */
 private static String input(Map<String,Object> theme,Texts texts){
  Map<String,Object> input=new LinkedHashMap<>();
  input.put("rule",theme.get("name"));input.put("engine",theme.get("module"));input.put("feedback_source",SOURCES.getOrDefault(String.valueOf(theme.get("source")),"feedback"));
  input.put("category",theme.get("category"));input.put("records",theme.get("records"));input.put("people",theme.get("people"));
  if(texts.complete()&&!texts.records().isEmpty())input.put("shared_terms",theme.get("terms"));
  if(texts.records().isEmpty())input.put("record_text","not included: this rule detects secrets, or no written text was recorded");else input.put("record_text",texts.records());
  try{return AssistantState.mapper().writeValueAsString(input);}catch(JsonProcessingException e){throw new IllegalStateException("Theme naming input could not be written",e);}
 }
 /** Up to 10 of the theme's newest records, redacted; bypasses that covered a secret finding are left out. */
 @SuppressWarnings("unchecked")
 private Texts texts(Map<String,Object> theme){
  var ids=((List<Object>)theme.getOrDefault("evidence",List.of())).stream().map(String::valueOf).limit(MAX_RECORDS).toList();
  if(ids.isEmpty())return Texts.NONE;long ruleId=((Number)theme.get("rule_id")).longValue();
  return switch(String.valueOf(theme.get("source"))){
   case "finding_feedback"->redacted(records.list(String.class,"SELECT f.explanation FROM FindingFeedbackEntity f WHERE f.occurrenceKey IN ?1 AND f.ruleId=?2",0,MAX_RECORDS,ids,ruleId),true);
   case "bypass"->bypassTexts(ids);
   case "review_outcome"->redacted(records.list(String.class,"SELECT i.outcome FROM RuleReviewItemEntity i WHERE i.reviewId IN ?1 AND i.ruleId=?2",0,MAX_RECORDS,ids,ruleId),true);
   default->Texts.NONE;
  };
 }
 private static Texts redacted(List<String> raw,boolean complete){return new Texts(raw.stream().map(ThemeNamingText::redact).filter(t->!t.isBlank()).toList(),complete);}
 /** A bypass that also covered a secret finding is left out, and then so are the theme's shared terms. */
 private Texts bypassTexts(List<String> ids){
  List<Long> bypassIds=new ArrayList<>();for(String id:ids){try{bypassIds.add(Long.parseLong(id));}catch(NumberFormatException ignored){/* not a bypass id */}}
  var covering=secrets.bypassesCoveringSecrets(bypassIds,secrets.secretRules());
  var allowed=bypassIds.stream().filter(id->!covering.contains(id)).toList();
  return allowed.isEmpty()?Texts.NONE:redacted(records.list(String.class,"SELECT b.reason FROM PullRequestBypassEntity b WHERE b.id IN ?1",0,MAX_RECORDS,allowed),covering.isEmpty());
 }
 @SuppressWarnings("unchecked")
 private static List<Map<String,Object>> themes(RuleReviewReportEntity report){
  try{
   var summary=AssistantState.mapper().readValue(report.getSummaryJson(),new TypeReference<Map<String,Object>>(){});
   var themes=(List<Map<String,Object>>)summary.getOrDefault("themes",List.of());
   // Reports written before R5.2b have no fingerprints and are not named.
   return themes.stream().filter(t->t.get("fingerprint") instanceof String).toList();
  }catch(JsonProcessingException e){throw new IllegalStateException("Stored review report unreadable",e);}
 }

 /** Reserves the worst case in this week's bucket; false when it would exceed the budget. */
 private boolean reserve(long bucket,long cost,long cap){
  return Boolean.TRUE.equals(tx.execute(s->{
   // Same lock order as chat budgets: the settings singleton first, then the bucket.
   records.lock(AssistantSettingsEntity.class,1);var row=bucket(bucket);
   if(Math.addExact(row.chargedCostMicros,cost)>cap)return false;
   row.chargedCostMicros+=cost;row.chargedTokens+=AssistantSettings.ThemeNaming.INPUT_TOKENS+AssistantSettings.ThemeNaming.OUTPUT_TOKENS;return true;
  }));
 }
 private void settle(long bucket,long reserved,long actual){
  if(actual>=reserved)return;
  tx.executeWithoutResult(s->{records.lock(AssistantSettingsEntity.class,1);var row=bucket(bucket);row.chargedCostMicros-=reserved-actual;});
 }
 private AssistantBudgetDailyEntity bucket(long bucket){
  var id=new AssistantBudgetDailyEntity.Id(BUDGET_SCOPE,bucket);var row=records.lock(AssistantBudgetDailyEntity.class,id);
  return row!=null?row:records.insert(new AssistantBudgetDailyEntity(BUDGET_SCOPE,bucket,0L,0L));
 }
 long spent(long bucket){var row=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(BUDGET_SCOPE,bucket));return row==null?0:row.chargedCostMicros;}
 long weekStart(){return LocalDate.now(clock.withZone(ZoneOffset.UTC)).with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();}
 private static long worstCase(AssistantSettings cfg){
  var naming=cfg.themeNaming();
  try{return cfg.model(naming.model(),naming.effort()).cost(AssistantSettings.ThemeNaming.INPUT_TOKENS,AssistantSettings.ThemeNaming.OUTPUT_TOKENS);}catch(IllegalArgumentException e){return 0;}
 }
 private static String sha256(String value){
  try{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
  catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}
 }
}

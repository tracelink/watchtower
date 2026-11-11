package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import java.time.LocalDate;

/** Explicitly validated Responses capabilities; model discovery never changes this allowlist. */
public record AssistantSettings(boolean enabled,int retentionDays,List<Model> allowedModels,
 String defaultModel,String defaultEffort,int maxIterations,int maxRequests,int maxInputBytes,
 int maxOutputTokens,int maxToolBytes,int maxTranscriptBytes,long turnTokenCap,long userDailyTokens,
 long orgDailyTokens,long turnCostMicros,long userDailyCostMicros,long orgDailyCostMicros,
 int queueLimit,int deadlineSeconds,int providerTimeoutSeconds,ThemeNaming themeNaming,FindingAssessment findingAssessment,boolean rulesetActionsEnabled,Features features) {
 public AssistantSettings(boolean enabled,int retentionDays,List<Model> allowedModels,
 String defaultModel,String defaultEffort,int maxIterations,int maxRequests,int maxInputBytes,
 int maxOutputTokens,int maxToolBytes,int maxTranscriptBytes,long turnTokenCap,long userDailyTokens,
 long orgDailyTokens,long turnCostMicros,long userDailyCostMicros,long orgDailyCostMicros,
 int queueLimit,int deadlineSeconds,int providerTimeoutSeconds,ThemeNaming themeNaming,FindingAssessment findingAssessment) { this(enabled,retentionDays,allowedModels,defaultModel,defaultEffort,maxIterations,maxRequests,maxInputBytes,maxOutputTokens,maxToolBytes,maxTranscriptBytes,turnTokenCap,userDailyTokens,orgDailyTokens,turnCostMicros,userDailyCostMicros,orgDailyCostMicros,queueLimit,deadlineSeconds,providerTimeoutSeconds,themeNaming,findingAssessment,false,null); }
 public AssistantSettings(boolean enabled,int retentionDays,List<Model> allowedModels,
 String defaultModel,String defaultEffort,int maxIterations,int maxRequests,int maxInputBytes,
 int maxOutputTokens,int maxToolBytes,int maxTranscriptBytes,long turnTokenCap,long userDailyTokens,
 long orgDailyTokens,long turnCostMicros,long userDailyCostMicros,long orgDailyCostMicros,
 int queueLimit,int deadlineSeconds,int providerTimeoutSeconds,ThemeNaming themeNaming,FindingAssessment findingAssessment,boolean rulesetActionsEnabled) { this(enabled,retentionDays,allowedModels,defaultModel,defaultEffort,maxIterations,maxRequests,maxInputBytes,maxOutputTokens,maxToolBytes,maxTranscriptBytes,turnTokenCap,userDailyTokens,orgDailyTokens,turnCostMicros,userDailyCostMicros,orgDailyCostMicros,queueLimit,deadlineSeconds,providerTimeoutSeconds,themeNaming,findingAssessment,rulesetActionsEnabled,null); }
 /**
  * Review-report theme naming (plan R5.2b): its own switch and weekly budget, separate from chat.
  * Settings stored before R5.2b have no entry and read as the default: off, $10 a week.
  */
 public record ThemeNaming(boolean enabled,String model,String effort,long weeklyCostMicros) {
  public static final ThemeNaming DEFAULT=new ThemeNaming(false,"","",10_000_000L);
  /** Worst case of one naming request; the prompt and record texts are bounded well below this. */
  public static final int INPUT_TOKENS=8000,OUTPUT_TOKENS=2048;
 }
 @Override public ThemeNaming themeNaming(){return themeNaming==null?ThemeNaming.DEFAULT:themeNaming;}
 /**
  * R6 advisory finding assessment: its own switch, off by default. It uses the chat default model and
  * effort and is charged to the requesting user's and the organization's daily chat budgets.
  */
 public record FindingAssessment(boolean enabled) {
  public static final FindingAssessment DEFAULT=new FindingAssessment(false);
  /** Worst case of one assessment request; evidence is bounded well below this. */
  public static final int INPUT_TOKENS=24000,OUTPUT_TOKENS=2048;
 }
 @Override public FindingAssessment findingAssessment(){return findingAssessment==null?FindingAssessment.DEFAULT:findingAssessment;}
 /**
  * Switches and daily slices for the AI features beyond chat. Settings stored before this existed have
  * neither map, so every feature reads as off. A slice caps one feature's share of the daily budget.
  */
 public record Features(Map<String,Boolean> enabled,Map<String,Slice> slices) {
  public static final Features DEFAULT=new Features(Map.of(),Map.of());
  public Features {
   if(enabled!=null&&enabled.entrySet().stream().anyMatch(e->e.getKey()==null||e.getValue()==null))throw new IllegalArgumentException("AI feature switches need a name and a value");
   if(slices!=null&&slices.entrySet().stream().anyMatch(e->e.getKey()==null||e.getValue()==null))throw new IllegalArgumentException("AI feature slices need a name and a daily cap");
   enabled=enabled==null?Map.of():Map.copyOf(enabled);
   slices=slices==null?Map.of():Map.copyOf(slices);
  }
  /** Most tokens and cost a feature may use in one UTC day, out of the shared organization budget. */
  public record Slice(long dailyTokens,long dailyCostMicros) { }
 }
 @Override public Features features(){return features==null?Features.DEFAULT:features;}
 public boolean isFeatureOn(AssistantFeature feature){return feature.isSwitchable()&&Boolean.TRUE.equals(features().enabled().get(feature.key()));}
 public Optional<Features.Slice> featureSlice(AssistantFeature feature){return Optional.ofNullable(features().slices().get(feature.key()));}
 private void validateFeatures(){
  var set=features();
  for(var key:set.enabled().keySet())if(AssistantFeature.ofKey(key).filter(AssistantFeature::isSwitchable).isEmpty())throw new IllegalArgumentException("Unknown AI feature: "+key);
  for(var entry:set.slices().entrySet()){
   var feature=AssistantFeature.ofKey(entry.getKey()).filter(AssistantFeature::hasSlice).orElseThrow(()->new IllegalArgumentException("No daily slice for AI feature: "+entry.getKey()));
   if(entry.getValue().dailyTokens()<1||entry.getValue().dailyCostMicros()<1)throw new IllegalArgumentException("The daily slice for "+feature.key()+" needs a positive token and cost cap");
  }
  for(var feature:AssistantFeature.values())if(isFeatureOn(feature)&&feature.needsSlice()&&featureSlice(feature).isEmpty())throw new IllegalArgumentException(feature.key()+" needs a daily slice before it can be turned on");
 }
 /** What the active slices set aside from the organization's daily budget, so chat always keeps the rest. */
 private long[] activeSlices(){
  long tokens=0,cost=0;
  for(var feature:AssistantFeature.values()){
   boolean active=feature==AssistantFeature.FINDING_ASSESSMENT?findingAssessment().enabled():isFeatureOn(feature);
   var slice=active?featureSlice(feature):Optional.<Features.Slice>empty();
   try{if(slice.isPresent()){tokens=Math.addExact(tokens,slice.get().dailyTokens());cost=Math.addExact(cost,slice.get().dailyCostMicros());}}
   catch(ArithmeticException e){throw new IllegalArgumentException("The AI feature slices add up to more than any organization budget");}
  }
  return new long[]{tokens,cost};
 }
 public record Model(String id,List<String> efforts,int inputTokenLimit,int outputTokenLimit,
   long inputMicrosPerMillion,long outputMicrosPerMillion,String validatedAt,String validationRef) {
  public void validate(){
   if(id==null||!id.matches("[A-Za-z0-9._:-]{1,128}")||efforts==null||efforts.isEmpty()||efforts.size()>8||efforts.stream().anyMatch(x->!Set.of("none","minimal","low","medium","high","xhigh","max","ultra","").contains(x))||inputTokenLimit<1024||inputTokenLimit>1000000||outputTokenLimit<128||outputTokenLimit>65536||inputMicrosPerMillion<0||outputMicrosPerMillion<0||inputMicrosPerMillion>1000000000L||outputMicrosPerMillion>1000000000L||validationRef==null||!validationRef.matches("[A-Za-z0-9._:/-]{1,128}"))throw new IllegalArgumentException("Invalid tested model capability");
   LocalDate.parse(validatedAt);
  }
  public long cost(long input,long output){return Math.addExact((Math.multiplyExact(input,inputMicrosPerMillion)+999999)/1000000,(Math.multiplyExact(output,outputMicrosPerMillion)+999999)/1000000);}
 }
 public Model model(String id,String effort){return allowedModels.stream().filter(m->m.id().equals(id)&&m.efforts().contains(effort)).findFirst().orElseThrow(()->new IllegalArgumentException("Model or effort unavailable; select an allowed model"));}
 private void validateThemeNaming(){
  var naming=themeNaming();
  if(naming.weeklyCostMicros()<1||naming.weeklyCostMicros()>1_000_000_000L)throw new IllegalArgumentException("Theme naming budget must be between $0.000001 and $1000 a week");
  if(!naming.enabled())return;
  var m=model(naming.model(),naming.effort());
  if(ThemeNaming.INPUT_TOKENS>m.inputTokenLimit()||ThemeNaming.OUTPUT_TOKENS>m.outputTokenLimit())throw new IllegalArgumentException("Theme naming needs a model with at least 8000 input and 2048 output tokens");
  if(m.cost(ThemeNaming.INPUT_TOKENS,ThemeNaming.OUTPUT_TOKENS)>naming.weeklyCostMicros())throw new IllegalArgumentException("Theme naming budget must permit one worst-case request");
 }
 public void validate(){
  if(retentionDays<1||retentionDays>15||allowedModels==null||allowedModels.size()>20||maxIterations<1||maxIterations>6||maxRequests<maxIterations||maxRequests>12||maxInputBytes<1024||maxInputBytes>65536||maxOutputTokens<128||maxOutputTokens>8192||maxToolBytes<512||maxToolBytes>16384||maxTranscriptBytes<maxInputBytes||maxTranscriptBytes>1048576||turnTokenCap<1||turnTokenCap>1000000||userDailyTokens<1||orgDailyTokens<1||turnCostMicros<1||userDailyCostMicros<1||orgDailyCostMicros<1||queueLimit<1||queueLimit>500||deadlineSeconds<60||deadlineSeconds>1800||providerTimeoutSeconds<5||providerTimeoutSeconds>60)throw new IllegalArgumentException("Invalid assistant limits");
  allowedModels.forEach(Model::validate);if(allowedModels.stream().map(Model::id).distinct().count()!=allowedModels.size())throw new IllegalArgumentException("Duplicate models");
  validateThemeNaming();validateFeatures();
  if(findingAssessment().enabled()){
   var m=model(defaultModel,defaultEffort);
   if(FindingAssessment.INPUT_TOKENS>m.inputTokenLimit()||FindingAssessment.OUTPUT_TOKENS>m.outputTokenLimit())throw new IllegalArgumentException("Finding assessment needs a default model with at least 24000 input and 2048 output tokens");
  }
  if(enabled){model(defaultModel,defaultEffort);long[] slices=activeSlices();for(Model m:allowedModels){if(maxOutputTokens>m.outputTokenLimit())throw new IllegalArgumentException("Output exceeds model limit");long reservation=(long)m.inputTokenLimit()+maxOutputTokens;long cost=m.cost(m.inputTokenLimit(),maxOutputTokens);if(reservation>turnTokenCap||reservation>userDailyTokens||reservation>orgDailyTokens||cost>turnCostMicros||cost>userDailyCostMicros||cost>orgDailyCostMicros)throw new IllegalArgumentException("Caps must permit one worst-case request for every allowed model");if(reservation>orgDailyTokens-slices[0]||cost>orgDailyCostMicros-slices[1])throw new IllegalArgumentException("The AI feature slices leave too little of the organization budget for one chat request");}}
 }
}

package com.tracelink.appsec.watchtower.core.assistant.features;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiProvider;

/**
 * One bounded, structured model request for an AI feature that is not chat (a bypass summary, a failure
 * diagnosis). It checks the feature's switch, the key and the default model, charges the feature's daily
 * slice and the shared buckets before the request leaves, and returns only the reply text. Nothing here
 * reads a finding, decides anything or writes a record.
 */
@Service
public class StructuredFeatureCall {
 private static final Logger LOG=LoggerFactory.getLogger(StructuredFeatureCall.class);
 /** A request is refused above this many tokens of input, estimated at one token per byte plus a margin. */
 public static final int MAX_INPUT_TOKENS=8000,MAX_OUTPUT_TOKENS=600;
 static final java.util.Set<String> REJECTED_BEFORE_PROCESSING=java.util.Set.of("PROVIDER_AUTHENTICATION","PROVIDER_RATE_LIMIT");
 /** The provider call; production uses the approved OpenAI Responses endpoint. */
 @FunctionalInterface public interface Provider { OpenAiLlmClient.StructuredReply call(OpenAiLlmClient.Structured request)throws IOException,InterruptedException; }
 /** Whether the feature can answer now, and if not, why in plain words. */
 public record Readiness(String problem,String message) { public boolean ready(){return problem==null;} }
 private final AssistantSettingsService settings;private final AiIntegrationService integrations;private final AssistantBudgetService budgets;private final Provider provider;
 @Autowired
 public StructuredFeatureCall(AssistantSettingsService settings,AiIntegrationService integrations,AssistantBudgetService budgets,OpenAiLlmClient client){this(settings,integrations,budgets,client::structured);}
 public StructuredFeatureCall(AssistantSettingsService settings,AiIntegrationService integrations,AssistantBudgetService budgets,Provider provider){this.settings=settings;this.integrations=integrations;this.budgets=budgets;this.provider=provider;}

 public Readiness readiness(AssistantFeature feature){
  var cfg=settings.get().settings();
  if(!cfg.enabled())return new Readiness("CHAT_OFF","Chat is turned off, and the AI features follow it. An Assistant Admin can turn it on in Assistant settings.");
  if(!cfg.isFeatureOn(feature))return new Readiness("OFF",feature.label()+" is off. An Assistant Admin can turn it on in Assistant settings.");
  var key=integrations.view(AiProvider.OPENAI);
  if(!key.configured())return new Readiness("NO_API_KEY","No OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.");
  if(Boolean.FALSE.equals(key.healthOk())&&"PROVIDER_AUTHENTICATION".equals(key.healthError()))return new Readiness("API_KEY_REJECTED","OpenAI rejected the configured API key. An Assistant Admin can test or replace it.");
  try{cfg.model(cfg.defaultModel(),cfg.defaultEffort());}catch(IllegalArgumentException e){return new Readiness("MODEL_UNAVAILABLE","Choose an allowed default model in Assistant settings.");}
  return new Readiness(null,"Ready.");
 }

 /**
  * Refuses with a 429 when the feature's daily share cannot cover one largest request. A feature that reads
  * source before it asks calls this first, so a used-up share costs no source-control work.
  */
 public void requireAffordable(String owner,AssistantFeature feature){requireAffordable(owner,feature,MAX_INPUT_TOKENS,MAX_OUTPUT_TOKENS);}

 /** As above, for a feature whose request and answer are larger than the usual bounds (a drafted rule). */
 public void requireAffordable(String owner,AssistantFeature feature,int maxInputTokens,int maxOutputTokens){
  var cfg=settings.get().settings();var model=cfg.model(cfg.defaultModel(),cfg.defaultEffort());
  if(!budgets.canAfford(owner,cfg,model,maxInputTokens,maxOutputTokens,feature))throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(feature,budgets.shortfall(owner,cfg,model,maxInputTokens,maxOutputTokens,feature)));
 }

 /**
  * Asks once and returns the reply text, or empty when the model refused or did not finish. A full daily
  * share is a 429; a provider failure is a 503 and keeps any uncertain charge, as other AI features do.
  */
 public Optional<String> ask(String owner,AssistantFeature feature,String instructions,String input,String schemaName,ObjectNode schema){
  return ask(owner,feature,instructions,input,schemaName,schema,MAX_INPUT_TOKENS,MAX_OUTPUT_TOKENS);
 }

 /**
  * As above with the feature's own bounds. The charge reserved and the request's output limit both use
  * {@code maxOutputTokens}, so a larger answer is paid for from the same daily share, never past it.
  */
 public Optional<String> ask(String owner,AssistantFeature feature,String instructions,String input,String schemaName,ObjectNode schema,int maxInputTokens,int maxOutputTokens){
  var ready=readiness(feature);
  if(!ready.ready())throw new ResponseStatusException(HttpStatus.CONFLICT,ready.message());
  var cfg=settings.get().settings();var model=cfg.model(cfg.defaultModel(),cfg.defaultEffort());
  long inputBound=(long)(instructions+input+schema).getBytes(StandardCharsets.UTF_8).length+256;
  if(inputBound>maxInputTokens)throw new IllegalArgumentException("There is too much to send; nothing was asked.");
  // Checked before anything else happens, so a full share costs nothing.
  if(!budgets.canAfford(owner,cfg,model,inputBound,maxOutputTokens,feature))throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(feature,budgets.shortfall(owner,cfg,model,inputBound,maxOutputTokens,feature)));
  AssistantBudgetService.Charge charge;
  try{charge=budgets.reserveDirect(owner,cfg,model,inputBound,maxOutputTokens,feature);}
  catch(IllegalStateException e){throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(feature,budgets.shortfall(owner,cfg,model,inputBound,maxOutputTokens,feature)));}
  OpenAiLlmClient.StructuredReply reply;
  try{
   reply=provider.call(new OpenAiLlmClient.Structured(model.id(),cfg.defaultEffort(),instructions,input,schemaName,schema,maxOutputTokens,cfg.providerTimeoutSeconds(),"watchtower-"+feature.key()));
  }catch(LlmClient.ProviderFailure e){
   // Only a request the provider refused before processing it is returned; any other failure may have been charged, so it stays reserved.
   if(REJECTED_BEFORE_PROCESSING.contains(e.code()))budgets.settleDirect(charge,0,0);
   LOG.warn("{} failed for {}: {}",feature.key(),owner,e.code());
   throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OpenAI could not answer right now; try again later.");
  }catch(IOException|RuntimeException e){LOG.warn("{} failed for {}: provider unavailable",feature.key(),owner);throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OpenAI could not answer right now; try again later.");}
  catch(InterruptedException e){Thread.currentThread().interrupt();throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Interrupted");}
  long tokens=reply.inputTokens()+reply.outputTokens();
  long actual=reply.usageKnown()&&tokens<=charge.tokens()?Math.min(charge.cost(),model.cost(reply.inputTokens(),reply.outputTokens())):charge.cost();
  if(actual<charge.cost())budgets.settleDirect(charge,Math.min(tokens,charge.tokens()),actual);
  boolean usable=!reply.refused()&&"completed".equals(reply.status());
  // Status only, never the reply: an unfinished or refused answer is otherwise indistinguishable from a bad one.
  if(!usable)LOG.warn("{} got no completed reply: status={}, refused={}",feature.key(),reply.status(),reply.refused());
  return usable?Optional.ofNullable(reply.text()):Optional.empty();
 }
}

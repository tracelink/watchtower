package com.tracelink.appsec.watchtower.core.assistant.integration;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.LlmClient.ProviderFailure;
import com.tracelink.appsec.watchtower.core.assistant.OpenAiLlmClient;

/** AI integration in Assistant admin: add, replace, remove and test a provider key. The key is write-only. */
@RestController
@RequestMapping("/admin/assistant/integrations/{provider}")
@PreAuthorize("hasAuthority('Assistant Admin')")
public class AiIntegrationController {
 public record Key(String apiKey,Long version){ }
 private final AiIntegrationService integrations;private final AssistantAccess access;private final OpenAiLlmClient client;
 public AiIntegrationController(AiIntegrationService integrations,AssistantAccess access,OpenAiLlmClient client){this.integrations=integrations;this.access=access;this.client=client;}
 @GetMapping public Object view(@PathVariable String provider,Authentication actor){return integrations.view(admin(provider,actor));}
 @PostMapping public Object save(@PathVariable String provider,@RequestBody Key key,Authentication actor){
  var p=admin(provider,actor);if(key==null||key.version()==null)throw new IllegalArgumentException("version is required");
  integrations.save(p,key.apiKey(),key.version(),actor.getName());return integrations.view(p);
 }
 @PostMapping("/remove") public Object remove(@PathVariable String provider,@RequestBody Key key,Authentication actor){
  var p=admin(provider,actor);if(key==null||key.version()==null)throw new IllegalArgumentException("version is required");
  integrations.remove(p,key.version(),actor.getName());return integrations.view(p);
 }
 /** Like Test connection for an SCM integration: lists models with the stored key and records the result. */
 @PostMapping("/test") public Object test(@PathVariable String provider,Authentication actor)throws InterruptedException{
  var p=admin(provider,actor);String error;
  try{int models=client.discover().size();integrations.recordHealth(p,true,null);return Map.of("ok",true,"message","Connected; the key can see "+models+" models.","integration",integrations.view(p));}
  catch(ProviderFailure e){error=e.code();}
  catch(IOException e){error="PROVIDER_TRANSPORT";}
  integrations.recordHealth(p,false,error);
  return Map.of("ok",false,"message",message(error),"integration",integrations.view(p));
 }
 static String message(String code){
  return switch(code){
   case "PROVIDER_AUTHENTICATION"->"OpenAI rejected the key, or no key is stored. Check that it is active and allowed to use models.";
   case "PROVIDER_TRANSPORT"->"Could not reach OpenAI from this server.";
   default->"OpenAI returned an error ("+code+").";
  };
 }
 private AiProvider admin(String provider,Authentication actor){
  access.require(actor.getName(),"Assistant Admin");
  return AiProvider.valueOf(provider.toUpperCase(Locale.ROOT));
 }
}

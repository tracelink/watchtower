package com.tracelink.appsec.watchtower.core.assistant;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.util.*;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService;
import com.tracelink.appsec.watchtower.core.assistant.integration.AiProvider;

/** Chat is controlled only from the UI: the shared "enabled" setting plus a usable stored provider key. */
@Service
public class AssistantSettingsService {
 /** Why chat can or cannot answer; the drawer shows {@code message} instead of hiding. */
 public record Readiness(boolean ready,String problem,String message){ }
 static final Readiness READY=new Readiness(true,null,"Chat is ready.");
 private final LedgerRepository records;private final AiIntegrationService integrations;private final boolean sharedStorageMissing;private final ObjectMapper mapper=new ObjectMapper();
 public AssistantSettingsService(LedgerRepository records,AiIntegrationService integrations,AssistantTranscriptStore store,
   @org.springframework.beans.factory.annotation.Value("${watchtower.cluster.multi-pod:false}")boolean multiPod){
  this.records=records;this.integrations=integrations;sharedStorageMissing=multiPod&&store instanceof LocalAssistantTranscriptStore;
 }
 public Readiness readiness(){
  var cfg=get().settings();
  if(cfg.allowedModels().isEmpty())return new Readiness(false,"NO_APPROVED_MODEL","No model is approved. An Assistant Admin can use Approve a model in Assistant settings; Chat can stay off during the synthetic compatibility check.");
  if(!cfg.enabled())return new Readiness(false,"CHAT_OFF","Chat is turned off. An Assistant Admin can turn it on in Assistant settings.");
  if(sharedStorageMissing)return new Readiness(false,"STORAGE","Chat needs shared S3 storage when Watchtower runs on several pods; ask the platform team to configure it.");
  var key=integrations.view(AiProvider.OPENAI);
  if(!key.configured())return new Readiness(false,"NO_API_KEY","No OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.");
  if(Boolean.FALSE.equals(key.healthOk())&&"PROVIDER_AUTHENTICATION".equals(key.healthError()))
   return new Readiness(false,"API_KEY_REJECTED","OpenAI rejected the configured API key. An Assistant Admin can test or replace it in Assistant settings → AI integration.");
  return READY;
 }
 public boolean available(){return readiness().ready();}
 public record Versioned(long version,AssistantSettings settings){ }
 public Versioned get(){var entity=records.find(AssistantSettingsEntity.class,1);if(entity==null)throw new IllegalStateException("Assistant settings missing");return new Versioned(entity.version,decode(entity.configJson));}
 public AssistantSettings decode(String json){try{var value=mapper.readValue(json,AssistantSettings.class);value.validate();return value;}catch(Exception e){throw new IllegalArgumentException("Invalid assistant settings");}}
 public String encode(AssistantSettings s){try{return mapper.writeValueAsString(s);}catch(Exception e){throw new IllegalArgumentException("Invalid settings");}}
 @Transactional
 public void save(Versioned v,String actor){if(v==null||v.settings()==null)throw new IllegalArgumentException("Settings are required");v.settings().validate();
  if(records.update("UPDATE AssistantSettingsEntity SET version=version+1,configJson=?1 WHERE settingsId=1 AND version=?2" ,encode(v.settings()),v.version())!=1)throw new ResponseStatusException(HttpStatus.CONFLICT,"Settings changed; reload");
  // Expired chats cannot be resurrected after their objects were handed to S3 lifecycle.
  records.update("UPDATE AssistantSessionEntity SET expiresAt=lastUserMessageAt+?1 WHERE transcriptPurgedAt IS NULL AND expiresAt>?2" ,v.settings().retentionDays()*86400000L,System.currentTimeMillis());
  records.insert(new AssistantAuditEntity(null,actor,null,null,"SETTINGS_CHANGED",Long.toString(v.version()+1),null,null,0L,0L,AssistantState.PROMPT_VERSION,AssistantState.TOOL_VERSION,System.currentTimeMillis()));
 }
}

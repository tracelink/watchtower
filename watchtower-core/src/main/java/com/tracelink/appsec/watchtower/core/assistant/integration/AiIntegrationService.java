package com.tracelink.appsec.watchtower.core.assistant.integration;

import java.util.Optional;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.persistence.AssistantAuditEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * The only reader and writer of AI provider keys, like the API settings page is for SCM credentials:
 * an Assistant Admin adds, replaces or removes a key; it is stored encrypted, never returned, and
 * every change is audited by who made it, never by value. Moving keys to AWS Secrets Manager later
 * replaces the storage behind this class without changing its callers.
 */
@Service
public class AiIntegrationService {
 private static final Logger LOG=LoggerFactory.getLogger(AiIntegrationService.class);
 /** OpenAI project, service-account and user keys: sk-, then letters, digits, '-' and '_'. */
 private static final Pattern OPENAI_KEY=Pattern.compile("sk-[A-Za-z0-9_-]{20,500}");
 private static final Pattern ERROR_CODE=Pattern.compile("[A-Z_]{1,64}");
 public record View(String provider,String name,boolean configured,String updatedBy,Long updatedAt,Long healthCheckedAt,Boolean healthOk,String healthError,long version,boolean encrypted){ }
 private final AiIntegrationRepository integrations;private final LedgerRepository records;private final boolean encrypted;
 public AiIntegrationService(AiIntegrationRepository integrations,LedgerRepository records,@Value("${watchtower.encryption.type:none}")EncryptionType encryption){
  this.integrations=integrations;this.records=records;encrypted=encryption!=EncryptionType.NONE;
 }
 /** The decrypted key for a provider call; read per call so a change applies on every pod at once. */
 public Optional<String> apiKey(AiProvider provider){return integrations.findById(provider).filter(AiIntegrationEntity::isConfigured).map(AiIntegrationEntity::getApiKey);}
 public View view(AiProvider provider){
  var e=integrations.findById(provider).orElseGet(()->new AiIntegrationEntity(provider));
  return new View(provider.name(),provider.displayName(),e.isConfigured(),e.getUpdatedBy(),e.getUpdatedAt(),e.getHealthCheckedAt(),e.getHealthOk(),e.getHealthError(),e.getVersion(),encrypted);
 }
 /** Adds or replaces the key; {@code version} is what the admin's form loaded, so a concurrent change is not overwritten. */
 @Transactional
 public void save(AiProvider provider,String apiKey,long version,String actor){
  String key=apiKey==null?"":apiKey.strip();
  if(!OPENAI_KEY.matcher(key).matches())throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Enter an OpenAI API key; it starts with sk-.");
  change(provider,key,version,actor,"AI_KEY_SAVED");
 }
 @Transactional
 public void remove(AiProvider provider,long version,String actor){change(provider,null,version,actor,"AI_KEY_REMOVED");}
 /** Records a connection check (the Test button, or the provider rejecting the key during chat). */
 public void recordHealth(AiProvider provider,boolean ok,String errorCode){
  String error=ok?null:errorCode!=null&&ERROR_CODE.matcher(errorCode).matches()?errorCode:"PROVIDER_ERROR";
  integrations.recordHealth(provider,System.currentTimeMillis(),ok,error);
 }
 private void change(AiProvider provider,String key,long version,String actor,String event){
  var e=integrations.findById(provider).orElseGet(()->new AiIntegrationEntity(provider));
  if(e.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"The key was changed by someone else; reload and try again.");
  long now=System.currentTimeMillis();e.setApiKey(key,actor,now);integrations.saveAndFlush(e);
  records.insert(new AssistantAuditEntity(null,actor,null,null,event,provider.name(),null,null,0L,0L,AssistantState.PROMPT_VERSION,AssistantState.TOOL_VERSION,now));
  LOG.info("{} API key {} by {}",provider.displayName(),key==null?"removed":"saved",actor);
 }
}

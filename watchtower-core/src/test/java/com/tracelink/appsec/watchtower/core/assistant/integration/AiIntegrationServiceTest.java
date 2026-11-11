package com.tracelink.appsec.watchtower.core.assistant.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.lang.reflect.Field;
import jakarta.persistence.Convert;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.data.repository.support.Repositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;

/** The OpenAI key on the real Flyway schema (V075): encrypted column, write-only, versioned, audited. */
@SpringBootTest(classes=WatchtowerTestApplication.class,properties={"watchtower.assistant.recovery-delay-ms=600000"})
class AiIntegrationServiceTest {
 static final String KEY="sk-proj-synthetic0000000000000000000000";
 @Autowired AiIntegrationService integrations;@Autowired JdbcTemplate jdbc;@Autowired ApplicationContext context;
 /** Stands in for the real cipher so the test can see exactly what reaches the column. */
 @MockitoBean DataEncryptionService encryption;
 @BeforeEach void reset(){
  when(encryption.encryptString(any(),eq(StringEncryptedAttributeConverter.class))).thenAnswer(i->i.getArgument(0)==null?null:"v2:cipher("+i.getArgument(0)+")");
  when(encryption.decryptString(any(),eq(StringEncryptedAttributeConverter.class))).thenAnswer(i->{String v=i.getArgument(0);return v==null?null:v.substring("v2:cipher(".length(),v.length()-1);});
  jdbc.update("UPDATE ai_integrations SET api_key=NULL,updated_by=NULL,updated_at=NULL,health_checked_at=NULL,health_ok=NULL,health_error=NULL,version=0 WHERE provider='OPENAI'");
  jdbc.update("DELETE FROM assistant_audit WHERE event LIKE 'AI_KEY_%'");
 }
 @Test void adminAddsReplacesAndRemovesTheKeyWhichIsStoredOnlyThroughTheEncryptingConverter(){
  var empty=integrations.view(AiProvider.OPENAI);assertFalse(empty.configured());assertTrue(integrations.apiKey(AiProvider.OPENAI).isEmpty());
  integrations.save(AiProvider.OPENAI,"  "+KEY+"\n",empty.version(),"admin");
  assertEquals("v2:cipher("+KEY+")",jdbc.queryForObject("SELECT api_key FROM ai_integrations WHERE provider='OPENAI'",String.class),"the column holds the converter's output, never the key as typed");
  assertEquals(KEY,integrations.apiKey(AiProvider.OPENAI).orElseThrow());
  var saved=integrations.view(AiProvider.OPENAI);assertTrue(saved.configured());assertEquals("admin",saved.updatedBy());
  assertFalse(saved.toString().contains(KEY),"the view never carries the key");

  assertEquals(409,assertThrows(ResponseStatusException.class,()->integrations.save(AiProvider.OPENAI,KEY+"x",empty.version(),"other")).getStatusCode().value(),"a stale form cannot overwrite a newer key");
  assertEquals(400,assertThrows(ResponseStatusException.class,()->integrations.save(AiProvider.OPENAI,"not-a-key",saved.version(),"admin")).getStatusCode().value());

  integrations.recordHealth(AiProvider.OPENAI,false,"PROVIDER_AUTHENTICATION");
  var failing=integrations.view(AiProvider.OPENAI);assertEquals(Boolean.FALSE,failing.healthOk());assertEquals("PROVIDER_AUTHENTICATION",failing.healthError());
  assertEquals(saved.version(),failing.version(),"a health check does not invalidate the admin's open form");
  integrations.recordHealth(AiProvider.OPENAI,false,"free text with sk-leak");assertEquals("PROVIDER_ERROR",integrations.view(AiProvider.OPENAI).healthError(),"only error codes are stored");

  integrations.save(AiProvider.OPENAI,KEY.replace('0','1'),failing.version(),"admin2");
  var replaced=integrations.view(AiProvider.OPENAI);assertNull(replaced.healthOk(),"a new key has not been tested");assertEquals("admin2",replaced.updatedBy());
  integrations.remove(AiProvider.OPENAI,replaced.version(),"admin");
  assertFalse(integrations.view(AiProvider.OPENAI).configured());assertNull(jdbc.queryForObject("SELECT api_key FROM ai_integrations WHERE provider='OPENAI'",String.class));
  assertEquals(3,jdbc.queryForObject("SELECT COUNT(*) FROM assistant_audit WHERE event LIKE 'AI_KEY_%' AND target='OPENAI'",Integer.class));
  assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM assistant_audit WHERE actor LIKE '%sk-%' OR target LIKE '%sk-%'",Integer.class),"audit rows never hold the key");
 }
 /** Key rotation re-encrypts only entities it can reach through a Spring Data repository. */
 @Test void keyRotationCanFindAndReEncryptTheKey()throws Exception{
  assertTrue(new Repositories(context).getRepositoryFor(AiIntegrationEntity.class).isPresent());
  Field key=AiIntegrationEntity.class.getDeclaredField("apiKey");
  assertEquals(StringEncryptedAttributeConverter.class,key.getAnnotation(Convert.class).converter(),"same converter, and so the same key handling, as Bitbucket credentials");
 }
}

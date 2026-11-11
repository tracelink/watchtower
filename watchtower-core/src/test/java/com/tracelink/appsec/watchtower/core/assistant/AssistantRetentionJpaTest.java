package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.persistence.*;

/** Real JPA behavior over an ORM-created in-memory schema; no migration scripts or AWS. */
class AssistantRetentionJpaTest {
 SessionFactory factory;JpaTransactionManager tx;LedgerRepository records;
 AssistantTranscriptStore store;AssistantMaintenance maintenance;long now;
 @BeforeEach void setup(){
  factory=new Configuration().addAnnotatedClass(AssistantSessionEntity.class).addAnnotatedClass(AssistantArtifactEntity.class)
   .addAnnotatedClass(AssistantTurnEntity.class).addAnnotatedClass(AssistantSettingsEntity.class).addAnnotatedClass(AssistantAuditEntity.class)
   .setProperty("hibernate.connection.driver_class","org.h2.Driver")
   .setProperty("hibernate.connection.url","jdbc:h2:mem:"+UUID.randomUUID()+";DB_CLOSE_DELAY=-1")
   .setProperty("hibernate.hbm2ddl.auto","create-drop").buildSessionFactory();
  tx=new JpaTransactionManager(factory);records=service(new LedgerRepository(SharedEntityManagerCreator.createSharedEntityManager(factory)));
  var db=mock(AssistantPersistence.class);store=mock(AssistantTranscriptStore.class);
  when(db.records()).thenReturn(records);when(db.store()).thenReturn(store);when(db.transaction()).thenReturn(new TransactionTemplate(tx));
  maintenance=new AssistantMaintenance(db);now=System.currentTimeMillis();
 }
 @SuppressWarnings("unchecked") <T>T service(T target){var proxy=new ProxyFactory(target);proxy.setProxyTargetClass(true);proxy.addAdvice(new TransactionInterceptor(tx,new AnnotationTransactionAttributeSource()));return (T)proxy.getProxy();}
 @AfterEach void close(){factory.close();}
 AssistantSessionEntity session(String id,long lastMessage,long expiry){
  var session=new AssistantSessionEntity(id,"owner",lastMessage,lastMessage,lastMessage,expiry,"model","low",1,id+"-artifact",null);
  records.insert(session);records.insert(new AssistantArtifactEntity(id+"-artifact",id,lastMessage,null));return session;
 }
 @Test void rollingExpiryPreservesActiveHistoryAndOnlyConfirmsPurgedAfterLifecycleRemoval()throws Exception{
  session("expired",now-15*86400000L,now-1);session("active",now-20*86400000L,now+14*86400000L);
  maintenance.retain();
  assertNull(records.find(AssistantArtifactEntity.class,"expired-artifact").deletedAt);
  assertNotNull(records.find(AssistantArtifactEntity.class,"expired-artifact").retentionCheckedAt);
  assertNull(records.find(AssistantSessionEntity.class,"expired").transcriptPurgedAt);
  verify(store,never()).expire("active-artifact");
  when(store.expire("expired-artifact")).thenReturn(true);maintenance.retain();
  assertNotNull(records.find(AssistantSessionEntity.class,"expired").transcriptPurgedAt);
  assertNull(records.find(AssistantSessionEntity.class,"active").transcriptPurgedAt);
 }
 @Test void pendingOrFailedLifecycleChecksDoNotStarveUnmarkedArtifacts()throws Exception{
  session("one",now-15*86400000L,now-1);session("two",now-14*86400000L,now-1);
  org.springframework.test.util.ReflectionTestUtils.setField(maintenance,"retentionBatchSize",1);
  maintenance.retain();maintenance.retain();
  verify(store).expire("one-artifact");verify(store).expire("two-artifact");
  assertNull(records.find(AssistantArtifactEntity.class,"one-artifact").deletedAt);
 }
 @Test void increasingRetentionExtendsActiveChatsWithoutResurrectingExpiredTaggedChats(){
  long last=now-13*86400000L;var expired=session("expired",last,now-1);session("active",last,now+86400000L);
  var settings=service(new AssistantSettingsService(records,mock(com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService.class),store,false));
  var config=new AssistantSettings(false,15,List.of(),"","",1,1,1024,128,512,2048,10000,10000,10000,10000,10000,10000,5,60,5,null,null);
  records.insert(new AssistantSettingsEntity(1,1L,settings.encode(config)));
  settings.save(new AssistantSettingsService.Versioned(1,config),"admin");
  assertEquals(expired.expiresAt,records.find(AssistantSessionEntity.class,"expired").expiresAt);
  assertEquals(last+15*86400000L,records.find(AssistantSessionEntity.class,"active").expiresAt);
 }
}

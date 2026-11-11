package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.s3.model.S3Exception;

class AssistantMaintenanceTest {
 @Test void minuteMaintenanceChecksTurnHealthWithoutTouchingTranscriptStorage() {
  var db=mock(AssistantPersistence.class);when(db.records()).thenReturn(mock(LedgerRepository.class));
  new AssistantMaintenance(db).maintain();
  verify(db,never()).store();verify(db.records(),never()).maps(anyString(),anyInt(),anyInt(),any(Object[].class));
 }
 @Test void lifecyclePendingIsNotFailureOrConfirmedDeletionAndReferencedArtifactsArePreserved() throws Exception {
  var db=mock(AssistantPersistence.class);var records=mock(LedgerRepository.class);
  var store=mock(AssistantTranscriptStore.class);var tx=mock(TransactionTemplate.class);
  when(db.records()).thenReturn(records);when(db.store()).thenReturn(store);when(db.transaction()).thenReturn(tx);
  doAnswer(i->{Consumer<TransactionStatus> action=i.getArgument(0);action.accept(new SimpleTransactionStatus());return null;}).when(tx).executeWithoutResult(any());
  when(records.maps(anyString(),eq(0),eq(1000),anyLong(),anyLong())).thenReturn(List.of(Map.of("artifact_key","pending","session_id","session")));
  when(store.expire("pending")).thenReturn(false);
  new AssistantMaintenance(db).retain();
  verify(records).update(contains("deletedAt=?2"),anyLong(),isNull(),eq("pending"));
  verify(db,never()).audit(anyString(),anyString(),any(),anyString(),any(),any(),any(),anyInt(),anyInt());
  var current=new com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity();current.expiresAt=System.currentTimeMillis()+86400000;
  when(records.lock(com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity.class,"session")).thenReturn(current);
  when(records.scalar(eq(Long.class),anyString(),eq("pending"))).thenReturn(1L);
  clearInvocations(store);new AssistantMaintenance(db).retain();verifyNoInteractions(store);
 }
 @Test void failuresProduceOneSafeBatchWarningAndAreRetriedWithoutMarkingDeleted() throws Exception {
  var db=mock(AssistantPersistence.class);var records=mock(LedgerRepository.class);
  var store=mock(AssistantTranscriptStore.class);var tx=mock(TransactionTemplate.class);
  when(db.records()).thenReturn(records);when(db.store()).thenReturn(store);when(db.transaction()).thenReturn(tx);
  doAnswer(i->{Consumer<TransactionStatus> action=i.getArgument(0);action.accept(new SimpleTransactionStatus());return null;}).when(tx).executeWithoutResult(any());
  when(records.maps(anyString(),eq(0),eq(1000),anyLong(),anyLong())).thenReturn(List.of(
   Map.of("artifact_key","first","session_id","session"),Map.of("artifact_key","second","session_id","session")));
  var denied=S3Exception.builder().statusCode(403).message("private object path and credentials")
   .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDenied").build()).build();
  when(store.expire(anyString())).thenThrow(new IOException("private transcript key",denied));
  Logger logger=(Logger)org.slf4j.LoggerFactory.getLogger(AssistantMaintenance.class);
  var log=new ListAppender<ILoggingEvent>();log.start();logger.addAppender(log);
  try {
   var maintenance=new AssistantMaintenance(db);maintenance.retain();
   assertEquals(1,log.list.size());String warning=log.list.getFirst().getFormattedMessage();
   assertTrue(warning.contains("2 expiry checks failed"));assertTrue(warning.contains("AccessDenied/HTTP403"));
   assertFalse(warning.contains("private"));assertNull(log.list.getFirst().getThrowableProxy());
   // One audit row per run with the count and sanitized cause, not one row per transcript.
   verify(db,times(1)).audit("system",null,null,"RETENTION_FAILED","STORAGE_RETENTION:2:S3Exception/AccessDenied/HTTP403",null,null,0,0);
   verify(records,never()).update(contains("deletedAt=?2"),anyLong(),any(),anyString());
   doReturn(true).when(store).expire(anyString());maintenance.retain();
   verify(store,times(2)).expire("first");verify(store,times(2)).expire("second");
   verify(records,times(2)).update(contains("deletedAt=?2"),anyLong(),anyLong(),anyString());
   assertEquals(1,log.list.size());
  } finally {logger.detachAppender(log);log.stop();}
 }
 @Test void recentRetentionFailuresAddUpPerRunCountsAndOlderPerTranscriptRows() {
  assertNull(AssistantRetentionStatus.summarize(List.of()));
  var status=AssistantRetentionStatus.summarize(List.of(
   Map.of("target","STORAGE_RETENTION:3:S3Exception/AccessDenied/HTTP403","created_at",30L),
   Map.of("target","STORAGE_RETENTION","created_at",20L),Map.of("target","STORAGE_RETENTION","created_at",10L)));
  assertEquals(5L,status.get("failures"));assertEquals(30L,status.get("last_failed_at"));
  assertEquals("S3Exception/AccessDenied/HTTP403",status.get("code"));
  assertEquals("STORAGE_RETENTION:1:UNKNOWN",AssistantMaintenance.retentionTarget(1,null));
 }
 @Test void unsafeProviderErrorCodesAndLocalPathsNeverEnterDiagnostics() {
  var unsafe=S3Exception.builder().statusCode(400).awsErrorDetails(AwsErrorDetails.builder().errorCode("secret\nobject/path").build()).build();
  assertEquals("S3Exception/UNKNOWN/HTTP400",AssistantMaintenance.deletionFailureCode(unsafe));
  assertEquals("IOException",AssistantMaintenance.deletionFailureCode(new IOException("/private/transcript")));
 }
}

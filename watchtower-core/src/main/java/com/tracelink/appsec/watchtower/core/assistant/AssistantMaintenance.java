package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/** Turn health is frequent; transcript expiry is daily and remains active with chat off. */
@Component
public class AssistantMaintenance {
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(AssistantMaintenance.class);
 private final AssistantPersistence db;
 @org.springframework.beans.factory.annotation.Value("${watchtower.assistant.retention-batch-size:1000}")
 private int retentionBatchSize=1000;
 public AssistantMaintenance(AssistantPersistence db){this.db=db;}
 @Scheduled(fixedDelayString="${watchtower.assistant.maintenance-delay-ms:60000}")
 @SchedulerLock(name="assistantTurnMaintenance",lockAtMostFor="PT5M",lockAtLeastFor="PT1S")
 public void maintain(){long now=System.currentTimeMillis();
  db.records().update("UPDATE AssistantTurnEntity SET status='FAILED',errorCode=CASE WHEN deadlineAt<=?1 THEN 'TURN_DEADLINE' ELSE 'RECOVERY_ATTEMPTS' END,leaseVersion=leaseVersion+1,activeUser=NULL,activeSession=NULL,updatedAt=?2 WHERE activeUser IS NOT NULL AND (deadlineAt<=?3 OR (attempts>=3 AND heartbeatAt<?4))" ,now,now,now,now-90000);
  db.records().update("UPDATE AssistantTurnEntity SET status='CANCELED',errorCode='CONVERSATION_EXPIRED',leaseVersion=leaseVersion+1,activeUser=NULL,activeSession=NULL,updatedAt=?1 WHERE activeUser IS NOT NULL AND sessionId IN (SELECT sessionId FROM AssistantSessionEntity WHERE expiresAt<=?2)" ,now,now);
  db.records().update("DELETE FROM AssistantOutboxEntity WHERE turnId IN (SELECT turnId FROM AssistantTurnEntity WHERE activeUser IS NULL)");
 }
 @Scheduled(cron="${watchtower.assistant.retention-cron:0 0 3 * * *}",zone="UTC")
 @SchedulerLock(name="assistantRetention",lockAtMostFor="PT30M",lockAtLeastFor="PT1S")
 public void retain(){long now=System.currentTimeMillis();
  var artifacts=db.records().maps("SELECT a.artifactKey AS artifact_key,a.sessionId AS session_id FROM AssistantArtifactEntity a LEFT JOIN AssistantSessionEntity s ON s.sessionId=a.sessionId WHERE a.deletedAt IS NULL AND (s.expiresAt<=?1 OR (a.createdAt<?2 AND NOT EXISTS (SELECT 1 FROM AssistantTurnEntity t WHERE t.checkpointKey=a.artifactKey) AND NOT EXISTS (SELECT 1 FROM AssistantSessionEntity current_session WHERE current_session.latestKey=a.artifactKey))) ORDER BY COALESCE(a.retentionCheckedAt,0),a.createdAt,a.artifactKey",0,Math.clamp(retentionBatchSize,1,1000) ,now,now-3600000);
  int failed=0;String failureCode=null;
  for(var a:artifacts){try{
   expireArtifact(a);
  }catch(DeleteFailure e){failed++;if(failureCode==null)failureCode=deletionFailureCode(e.getCause());db.records().update("UPDATE AssistantArtifactEntity SET retentionCheckedAt=?1 WHERE artifactKey=?2",System.currentTimeMillis(),a.get("artifact_key"));}}
  if(failed>0){
   LOG.warn("Assistant transcript retention: {} expiry checks failed ({}); retrying in the next daily retention batch",failed,failureCode);
   // One audit row per run (not per transcript), carrying the count and the sanitized cause.
   db.audit("system",null,null,"RETENTION_FAILED",retentionTarget(failed,failureCode),null,null,0,0);
  }
  db.records().update("UPDATE AssistantSessionEntity s SET s.transcriptPurgedAt=?1 WHERE s.transcriptPurgedAt IS NULL AND s.expiresAt<=?2 AND NOT EXISTS (SELECT a.artifactKey FROM AssistantArtifactEntity a WHERE a.sessionId=s.sessionId AND a.deletedAt IS NULL)" ,now,now);
 }
 private void expireArtifact(java.util.Map<String,Object> a){
  db.transaction().executeWithoutResult(tx->{
   String session=(String)a.get("session_id");var current=db.records().lock(com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity.class,session);
   if(current!=null&&current.expiresAt>System.currentTimeMillis()){
    // Recheck after taking the publication lock: a candidate may have been published meanwhile.
    if(db.records().scalar(Long.class,"SELECT COUNT(*) FROM AssistantTurnEntity WHERE checkpointKey=?1" ,a.get("artifact_key"))>0||db.records().scalar(Long.class,"SELECT COUNT(*) FROM AssistantSessionEntity WHERE latestKey=?1" ,a.get("artifact_key"))>0)return;
   }
   boolean absent;try{absent=db.store().expire((String)a.get("artifact_key"));}catch(IOException e){throw new DeleteFailure(e);}
   db.records().update("UPDATE AssistantArtifactEntity SET retentionCheckedAt=?1,deletedAt=?2 WHERE artifactKey=?3" ,System.currentTimeMillis(),absent?System.currentTimeMillis():null,a.get("artifact_key"));
  });
 }
 /**
  * Removes the stored copies of one chat the person just deleted, right away, with the same expiry the daily job uses.
  * A copy that cannot be removed now is left marked and the daily job retries it, so a storage outage never loses the deletion.
  */
 public void purgeSession(String sessionId){
  var artifacts=db.records().maps("SELECT a.artifactKey AS artifact_key,a.sessionId AS session_id FROM AssistantArtifactEntity a WHERE a.sessionId=?1 AND a.deletedAt IS NULL",0,1000 ,sessionId);
  int failed=0;String failureCode=null;
  for(var a:artifacts){try{expireArtifact(a);}catch(DeleteFailure e){failed++;if(failureCode==null)failureCode=deletionFailureCode(e.getCause());}}
  if(failed>0)LOG.warn("Assistant chat deletion: {} stored copies not removed yet ({}); the daily retention job will retry",failed,failureCode);
  db.records().update("UPDATE AssistantSessionEntity s SET s.transcriptPurgedAt=?1 WHERE s.sessionId=?2 AND s.transcriptPurgedAt IS NULL AND s.expiresAt<=?1 AND NOT EXISTS (SELECT a.artifactKey FROM AssistantArtifactEntity a WHERE a.sessionId=s.sessionId AND a.deletedAt IS NULL)" ,System.currentTimeMillis(),sessionId);
 }
 /** "STORAGE_RETENTION:20:S3Exception/AccessDenied/HTTP403": the count and the sanitized code only. */
 static String retentionTarget(int failed,String failureCode){
  String target="STORAGE_RETENTION:"+failed+":"+(failureCode==null?"UNKNOWN":failureCode);
  return target.length()>255?target.substring(0,255):target;
 }
 /** Never include exception messages, object keys or transcript content in logs. */
 static String deletionFailureCode(Throwable failure){
  String code=failure.getClass().getSimpleName();
  for(Throwable cause=failure;cause!=null;cause=cause.getCause()){
   if(cause instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws){
    String serviceCode=aws.awsErrorDetails()==null?null:aws.awsErrorDetails().errorCode();
    return aws.getClass().getSimpleName()+"/"+(serviceCode!=null&&serviceCode.matches("[A-Za-z0-9_.-]{1,80}")?serviceCode:"UNKNOWN")+"/HTTP"+aws.statusCode();
   }
   if(cause instanceof software.amazon.awssdk.core.exception.SdkClientException)code="SdkClientException";
  }
  return code;
 }
 private static class DeleteFailure extends RuntimeException { DeleteFailure(IOException cause){super(cause);} }
}

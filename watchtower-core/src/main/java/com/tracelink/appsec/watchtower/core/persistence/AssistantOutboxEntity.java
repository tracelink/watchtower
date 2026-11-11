package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_outbox")
public class AssistantOutboxEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="turn_id", nullable=false, length=36)
 public String turnId;
 @Column(name="session_id", nullable=false, length=36)
 public String sessionId;
 @Column(name="sent_at", nullable=true)
 public Long sentAt;
 @Column(name="attempts", nullable=false)
 public Integer attempts;
 @Column(name="next_attempt_at", nullable=false)
 public Long nextAttemptAt;
 public AssistantOutboxEntity() { }
 public AssistantOutboxEntity(String turnId, String sessionId, Long sentAt, Integer attempts, Long nextAttemptAt) {
  this.turnId=turnId;
  this.sessionId=sessionId;
  this.sentAt=sentAt;
  this.attempts=attempts;
  this.nextAttemptAt=nextAttemptAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("turn_id",turnId);
  values.put("session_id",sessionId);
  values.put("sent_at",sentAt);
  values.put("attempts",attempts);
  values.put("next_attempt_at",nextAttemptAt);
  return values;
 }
}

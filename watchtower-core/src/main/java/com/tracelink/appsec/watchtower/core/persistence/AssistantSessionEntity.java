package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_sessions")
public class AssistantSessionEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="session_id", nullable=false, length=36)
 public String sessionId;
 @Column(name="owner", nullable=false, length=255)
 public String owner;
 @Column(name="started_at", nullable=false)
 public Long startedAt;
 @Column(name="last_user_message_at", nullable=false)
 public Long lastUserMessageAt;
 @Column(name="last_turn_at", nullable=false)
 public Long lastTurnAt;
 @Column(name="expires_at", nullable=false)
 public Long expiresAt;
 @Column(name="model", nullable=false, length=128)
 public String model;
 @Column(name="effort", nullable=false, length=24)
 public String effort;
 @Column(name="turn_count", nullable=false)
 public Integer turnCount;
 @Column(name="latest_key", nullable=true, length=255)
 public String latestKey;
 @Column(name="transcript_purged_at", nullable=true)
 public Long transcriptPurgedAt;
 @Column(name="title", nullable=true, length=120)
 public String title;
 public AssistantSessionEntity() { }
 public AssistantSessionEntity(String sessionId, String owner, Long startedAt, Long lastUserMessageAt, Long lastTurnAt, Long expiresAt, String model, String effort, Integer turnCount, String latestKey, Long transcriptPurgedAt) {
  this.sessionId=sessionId;
  this.owner=owner;
  this.startedAt=startedAt;
  this.lastUserMessageAt=lastUserMessageAt;
  this.lastTurnAt=lastTurnAt;
  this.expiresAt=expiresAt;
  this.model=model;
  this.effort=effort;
  this.turnCount=turnCount;
  this.latestKey=latestKey;
  this.transcriptPurgedAt=transcriptPurgedAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("session_id",sessionId);
  values.put("owner",owner);
  values.put("started_at",startedAt);
  values.put("last_user_message_at",lastUserMessageAt);
  values.put("last_turn_at",lastTurnAt);
  values.put("expires_at",expiresAt);
  values.put("model",model);
  values.put("effort",effort);
  values.put("turn_count",turnCount);
  values.put("latest_key",latestKey);
  values.put("transcript_purged_at",transcriptPurgedAt);
  values.put("title",title);
  return values;
 }
}

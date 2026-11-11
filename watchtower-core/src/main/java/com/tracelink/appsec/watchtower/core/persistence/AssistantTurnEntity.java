package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_turns")
public class AssistantTurnEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="turn_id", nullable=false, length=36)
 public String turnId;
 @Column(name="session_id", nullable=false, length=36)
 public String sessionId;
 @Column(name="owner", nullable=false, length=255)
 public String owner;
 @Column(name="idempotency_key", nullable=false, length=36)
 public String idempotencyKey;
 @Column(name="request_hash", nullable=false, length=64)
 public String requestHash;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="model", nullable=false, length=128)
 public String model;
 @Column(name="effort", nullable=false, length=24)
 public String effort;
 @Column(name="settings_json", nullable=false, columnDefinition="TEXT")
 public String settingsJson;
 @Column(name="checkpoint_key", nullable=false, length=255)
 public String checkpointKey;
 @Column(name="lease_owner", nullable=true, length=36)
 public String leaseOwner;
 @Column(name="lease_version", nullable=false)
 public Long leaseVersion;
 @Column(name="heartbeat_at", nullable=true)
 public Long heartbeatAt;
 @Column(name="attempts", nullable=false)
 public Integer attempts;
 @Column(name="deadline_at", nullable=false)
 public Long deadlineAt;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 @Column(name="updated_at", nullable=false)
 public Long updatedAt;
 @Column(name="tokens", nullable=false)
 public Long tokens;
 @Column(name="cost_micros", nullable=false)
 public Long costMicros;
 @Column(name="error_code", nullable=true, length=64)
 public String errorCode;
 @Column(name="active_user", nullable=true, length=64)
 public String activeUser;
 @Column(name="active_session", nullable=true, length=36)
 public String activeSession;
 public AssistantTurnEntity() { }
 public AssistantTurnEntity(String turnId, String sessionId, String owner, String idempotencyKey, String requestHash, String status, String model, String effort, String settingsJson, String checkpointKey, String leaseOwner, Long leaseVersion, Long heartbeatAt, Integer attempts, Long deadlineAt, Long createdAt, Long updatedAt, Long tokens, Long costMicros, String errorCode, String activeUser, String activeSession) {
  this.turnId=turnId;
  this.sessionId=sessionId;
  this.owner=owner;
  this.idempotencyKey=idempotencyKey;
  this.requestHash=requestHash;
  this.status=status;
  this.model=model;
  this.effort=effort;
  this.settingsJson=settingsJson;
  this.checkpointKey=checkpointKey;
  this.leaseOwner=leaseOwner;
  this.leaseVersion=leaseVersion;
  this.heartbeatAt=heartbeatAt;
  this.attempts=attempts;
  this.deadlineAt=deadlineAt;
  this.createdAt=createdAt;
  this.updatedAt=updatedAt;
  this.tokens=tokens;
  this.costMicros=costMicros;
  this.errorCode=errorCode;
  this.activeUser=activeUser;
  this.activeSession=activeSession;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("turn_id",turnId);
  values.put("session_id",sessionId);
  values.put("owner",owner);
  values.put("idempotency_key",idempotencyKey);
  values.put("request_hash",requestHash);
  values.put("status",status);
  values.put("model",model);
  values.put("effort",effort);
  values.put("settings_json",settingsJson);
  values.put("checkpoint_key",checkpointKey);
  values.put("lease_owner",leaseOwner);
  values.put("lease_version",leaseVersion);
  values.put("heartbeat_at",heartbeatAt);
  values.put("attempts",attempts);
  values.put("deadline_at",deadlineAt);
  values.put("created_at",createdAt);
  values.put("updated_at",updatedAt);
  values.put("tokens",tokens);
  values.put("cost_micros",costMicros);
  values.put("error_code",errorCode);
  values.put("active_user",activeUser);
  values.put("active_session",activeSession);
  return values;
 }
}

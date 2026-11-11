package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_audit")
public class AssistantAuditEntity implements LedgerRecord {
 @jakarta.persistence.Id @GeneratedValue(strategy=GenerationType.IDENTITY) @Column(name="audit_id", nullable=false)
 public Long auditId;
 @Column(name="actor", nullable=false, length=255)
 public String actor;
 @Column(name="session_id", nullable=true, length=36)
 public String sessionId;
 @Column(name="turn_id", nullable=true, length=36)
 public String turnId;
 @Column(name="event", nullable=false, length=64)
 public String event;
 @Column(name="target", nullable=true, length=255)
 public String target;
 @Column(name="model", nullable=true, length=128)
 public String model;
 @Column(name="effort", nullable=true, length=24)
 public String effort;
 @Column(name="tokens", nullable=false)
 public Long tokens;
 @Column(name="cost_micros", nullable=false)
 public Long costMicros;
 @Column(name="prompt_version", nullable=false, length=24)
 public String promptVersion;
 @Column(name="tool_version", nullable=false, length=24)
 public String toolVersion;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public AssistantAuditEntity() { }
 public AssistantAuditEntity(Long auditId, String actor, String sessionId, String turnId, String event, String target, String model, String effort, Long tokens, Long costMicros, String promptVersion, String toolVersion, Long createdAt) {
  this.auditId=auditId;
  this.actor=actor;
  this.sessionId=sessionId;
  this.turnId=turnId;
  this.event=event;
  this.target=target;
  this.model=model;
  this.effort=effort;
  this.tokens=tokens;
  this.costMicros=costMicros;
  this.promptVersion=promptVersion;
  this.toolVersion=toolVersion;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("audit_id",auditId);
  values.put("actor",actor);
  values.put("session_id",sessionId);
  values.put("turn_id",turnId);
  values.put("event",event);
  values.put("target",target);
  values.put("model",model);
  values.put("effort",effort);
  values.put("tokens",tokens);
  values.put("cost_micros",costMicros);
  values.put("prompt_version",promptVersion);
  values.put("tool_version",toolVersion);
  values.put("created_at",createdAt);
  return values;
 }
}

package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_artifacts")
public class AssistantArtifactEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="artifact_key", nullable=false, length=255)
 public String artifactKey;
 @Column(name="session_id", nullable=false, length=36)
 public String sessionId;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 @Column(name="deleted_at", nullable=true)
 public Long deletedAt;
 @Column(name="retention_checked_at")
 public Long retentionCheckedAt;
 public AssistantArtifactEntity() { }
 public AssistantArtifactEntity(String artifactKey, String sessionId, Long createdAt, Long deletedAt) {
  this.artifactKey=artifactKey;
  this.sessionId=sessionId;
  this.createdAt=createdAt;
  this.deletedAt=deletedAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("artifact_key",artifactKey);
  values.put("session_id",sessionId);
  values.put("created_at",createdAt);
  values.put("deleted_at",deletedAt);
  values.put("retention_checked_at",retentionCheckedAt);
  return values;
 }
}

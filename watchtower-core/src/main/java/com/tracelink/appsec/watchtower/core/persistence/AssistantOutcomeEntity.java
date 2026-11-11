package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_outcomes")
public class AssistantOutcomeEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="turn_id", nullable=false, length=36)
 public String turnId;
 @Column(name="owner", nullable=false, length=255)
 public String owner;
 @Column(name="rating", nullable=true)
 public Integer rating;
 @Column(name="task_type", nullable=true, length=24)
 public String taskType;
 @Column(name="elapsed_seconds", nullable=true)
 public Long elapsedSeconds;
 @Column(name="saved_seconds", nullable=true)
 public Long savedSeconds;
 @Column(name="updated_at", nullable=false)
 public Long updatedAt;
 public AssistantOutcomeEntity() { }
 public AssistantOutcomeEntity(String turnId, String owner, Integer rating, String taskType, Long elapsedSeconds, Long savedSeconds, Long updatedAt) {
  this.turnId=turnId;
  this.owner=owner;
  this.rating=rating;
  this.taskType=taskType;
  this.elapsedSeconds=elapsedSeconds;
  this.savedSeconds=savedSeconds;
  this.updatedAt=updatedAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("turn_id",turnId);
  values.put("owner",owner);
  values.put("rating",rating);
  values.put("task_type",taskType);
  values.put("elapsed_seconds",elapsedSeconds);
  values.put("saved_seconds",savedSeconds);
  values.put("updated_at",updatedAt);
  return values;
 }
}

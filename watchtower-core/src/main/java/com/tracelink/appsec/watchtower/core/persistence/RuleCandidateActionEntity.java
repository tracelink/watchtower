package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_candidate_actions")
public class RuleCandidateActionEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="action_id", nullable=false, length=36)
 public String actionId;
 @Column(name="candidate_id", nullable=false, length=36)
 public String candidateId;
 @Column(name="action", nullable=false, length=24)
 public String action;
 @Column(name="revision", nullable=false, length=64)
 public String revision;
 @Column(name="run_id", nullable=true, length=36)
 public String runId;
 @Column(name="evidence_hash", nullable=true, length=64)
 public String evidenceHash;
 @Column(name="actor", nullable=false, length=255)
 public String actor;
 @Column(name="rationale", nullable=false, length=300)
 public String rationale;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public RuleCandidateActionEntity() { }
 public RuleCandidateActionEntity(String actionId, String candidateId, String action, String revision, String runId, String evidenceHash, String actor, String rationale, Long createdAt) {
  this.actionId=actionId;
  this.candidateId=candidateId;
  this.action=action;
  this.revision=revision;
  this.runId=runId;
  this.evidenceHash=evidenceHash;
  this.actor=actor;
  this.rationale=rationale;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("action_id",actionId);
  values.put("candidate_id",candidateId);
  values.put("action",action);
  values.put("revision",revision);
  values.put("run_id",runId);
  values.put("evidence_hash",evidenceHash);
  values.put("actor",actor);
  values.put("rationale",rationale);
  values.put("created_at",createdAt);
  return values;
 }
}

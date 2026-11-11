package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_shadow_observations")
public class RuleShadowObservationEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="observation_id", nullable=false, length=64)
 public String observationId;
 @Column(name="candidate_id", nullable=false, length=36)
 public String candidateId;
 @Column(name="scan_type", nullable=false, length=24)
 public String scanType;
 @Column(name="scan_id", nullable=false)
 public Long scanId;
 @Column(name="base_revision", nullable=false, length=64)
 public String baseRevision;
 @Column(name="candidate_revision", nullable=false, length=64)
 public String candidateRevision;
 @Column(name="execution_identity", nullable=false, length=64)
 public String executionIdentity;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="evidence_json", nullable=false, columnDefinition="LONGTEXT")
 public String evidenceJson;
 @Column(name="elapsed_millis", nullable=false)
 public Long elapsedMillis;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public RuleShadowObservationEntity() { }
 public RuleShadowObservationEntity(String observationId, String candidateId, String scanType, Long scanId, String baseRevision, String candidateRevision, String executionIdentity, String status, String evidenceJson, Long elapsedMillis, Long createdAt) {
  this.observationId=observationId;
  this.candidateId=candidateId;
  this.scanType=scanType;
  this.scanId=scanId;
  this.baseRevision=baseRevision;
  this.candidateRevision=candidateRevision;
  this.executionIdentity=executionIdentity;
  this.status=status;
  this.evidenceJson=evidenceJson;
  this.elapsedMillis=elapsedMillis;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("observation_id",observationId);
  values.put("candidate_id",candidateId);
  values.put("scan_type",scanType);
  values.put("scan_id",scanId);
  values.put("base_revision",baseRevision);
  values.put("candidate_revision",candidateRevision);
  values.put("execution_identity",executionIdentity);
  values.put("status",status);
  values.put("evidence_json",evidenceJson);
  values.put("elapsed_millis",elapsedMillis);
  values.put("created_at",createdAt);
  return values;
 }
}

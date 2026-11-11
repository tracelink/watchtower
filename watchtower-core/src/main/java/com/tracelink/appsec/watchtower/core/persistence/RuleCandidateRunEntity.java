package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_candidate_runs")
public class RuleCandidateRunEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="run_id", nullable=false, length=36)
 public String runId;
 @Column(name="candidate_id", nullable=false, length=36)
 public String candidateId;
 @Column(name="base_revision", nullable=false, length=64)
 public String baseRevision;
 @Column(name="candidate_revision", nullable=false, length=64)
 public String candidateRevision;
 @Column(name="evidence_hash", nullable=false, length=64)
 public String evidenceHash;
 @Column(name="evidence_json", nullable=false, columnDefinition="LONGTEXT")
 public String evidenceJson;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="actor", nullable=false, length=255)
 public String actor;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 @Column(name="active_candidate", nullable=true, length=36)
 public String activeCandidate;
 @Column(name="claim_token", nullable=true, length=36)
 public String claimToken;
 @Column(name="lease_until", nullable=true)
 public Long leaseUntil;
 public RuleCandidateRunEntity() { }
 public RuleCandidateRunEntity(String runId, String candidateId, String baseRevision, String candidateRevision, String evidenceHash, String evidenceJson, String status, String actor, Long createdAt, String activeCandidate, String claimToken, Long leaseUntil) {
  this.runId=runId;
  this.candidateId=candidateId;
  this.baseRevision=baseRevision;
  this.candidateRevision=candidateRevision;
  this.evidenceHash=evidenceHash;
  this.evidenceJson=evidenceJson;
  this.status=status;
  this.actor=actor;
  this.createdAt=createdAt;
  this.activeCandidate=activeCandidate;
  this.claimToken=claimToken;
  this.leaseUntil=leaseUntil;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("run_id",runId);
  values.put("candidate_id",candidateId);
  values.put("base_revision",baseRevision);
  values.put("candidate_revision",candidateRevision);
  values.put("evidence_hash",evidenceHash);
  values.put("evidence_json",evidenceJson);
  values.put("status",status);
  values.put("actor",actor);
  values.put("created_at",createdAt);
  values.put("active_candidate",activeCandidate);
  values.put("claim_token",claimToken);
  values.put("lease_until",leaseUntil);
  return values;
 }
}

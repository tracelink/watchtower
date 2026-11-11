package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_candidates")
public class RuleCandidateEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="candidate_id", nullable=false, length=36)
 public String candidateId;
 @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @Column(name="base_revision", nullable=false, length=64)
 public String baseRevision;
 @Column(name="base_definition_hash", nullable=false, length=64)
 public String baseDefinitionHash;
 @Column(name="revision", nullable=false, length=64)
 public String revision;
 @Column(name="definition_json", nullable=false, columnDefinition="LONGTEXT")
 public String definitionJson;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="rationale", nullable=false, length=300)
 public String rationale;
 @Column(name="reviewer", nullable=false, length=255)
 public String reviewer;
 @Column(name="review_id", nullable=true, length=36)
 public String reviewId;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 @Column(name="updated_at", nullable=false)
 public Long updatedAt;
 @Column(name="version", nullable=false)
 public Long version;
 public RuleCandidateEntity() { }
 public RuleCandidateEntity(String candidateId, Long ruleId, String baseRevision, String baseDefinitionHash, String revision, String definitionJson, String status, String rationale, String reviewer, String reviewId, Long createdAt, Long updatedAt, Long version) {
  this.candidateId=candidateId;
  this.ruleId=ruleId;
  this.baseRevision=baseRevision;
  this.baseDefinitionHash=baseDefinitionHash;
  this.revision=revision;
  this.definitionJson=definitionJson;
  this.status=status;
  this.rationale=rationale;
  this.reviewer=reviewer;
  this.reviewId=reviewId;
  this.createdAt=createdAt;
  this.updatedAt=updatedAt;
  this.version=version;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("candidate_id",candidateId);
  values.put("rule_id",ruleId);
  values.put("base_revision",baseRevision);
  values.put("base_definition_hash",baseDefinitionHash);
  values.put("revision",revision);
  values.put("definition_json",definitionJson);
  values.put("status",status);
  values.put("rationale",rationale);
  values.put("reviewer",reviewer);
  values.put("review_id",reviewId);
  values.put("created_at",createdAt);
  values.put("updated_at",updatedAt);
  values.put("version",version);
  return values;
 }
}

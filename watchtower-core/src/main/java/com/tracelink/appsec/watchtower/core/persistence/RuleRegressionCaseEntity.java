package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_regression_cases")
public class RuleRegressionCaseEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="case_id", nullable=false, length=36)
 public String caseId;
 @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="case_kind", nullable=false, length=24)
 public String caseKind;
 @Column(name="fixture_ref", nullable=false, length=255)
 public String fixtureRef;
 @Column(name="fixture_hash", nullable=false, length=64)
 public String fixtureHash;
 @Column(name="expected_behavior", nullable=false, length=24)
 public String expectedBehavior;
 @Column(name="engine", nullable=false, length=64)
 public String engine;
 @Column(name="language", nullable=false, length=64)
 public String language;
 @Column(name="reviewer", nullable=false, length=255)
 public String reviewer;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public RuleRegressionCaseEntity() { }
 public RuleRegressionCaseEntity(String caseId, Long ruleId, String revision, String caseKind, String fixtureRef, String fixtureHash, String expectedBehavior, String engine, String language, String reviewer, Long createdAt) {
  this.caseId=caseId;
  this.ruleId=ruleId;
  this.revision=revision;
  this.caseKind=caseKind;
  this.fixtureRef=fixtureRef;
  this.fixtureHash=fixtureHash;
  this.expectedBehavior=expectedBehavior;
  this.engine=engine;
  this.language=language;
  this.reviewer=reviewer;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("case_id",caseId);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("case_kind",caseKind);
  values.put("fixture_ref",fixtureRef);
  values.put("fixture_hash",fixtureHash);
  values.put("expected_behavior",expectedBehavior);
  values.put("engine",engine);
  values.put("language",language);
  values.put("reviewer",reviewer);
  values.put("created_at",createdAt);
  return values;
 }
}

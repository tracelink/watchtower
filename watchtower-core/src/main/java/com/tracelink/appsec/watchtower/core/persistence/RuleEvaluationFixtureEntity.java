package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_evaluation_fixtures")
public class RuleEvaluationFixtureEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="fixture_id", nullable=false, length=36)
 public String fixtureId;
 @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @Column(name="fixture_ref", nullable=false, length=255)
 public String fixtureRef;
 @Column(name="fixture_hash", nullable=false, length=64)
 public String fixtureHash;
 @Column(name="expected_behavior", nullable=false, length=24)
 public String expectedBehavior;
 @Column(name="cohort", nullable=false, length=24)
 public String cohort;
 @Column(name="reviewer", nullable=false, length=255)
 public String reviewer;
 @Column(name="evidence_ref", nullable=false, length=255)
 public String evidenceRef;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public RuleEvaluationFixtureEntity() { }
 public RuleEvaluationFixtureEntity(String fixtureId, Long ruleId, String fixtureRef, String fixtureHash, String expectedBehavior, String cohort, String reviewer, String evidenceRef, Long createdAt) {
  this.fixtureId=fixtureId;
  this.ruleId=ruleId;
  this.fixtureRef=fixtureRef;
  this.fixtureHash=fixtureHash;
  this.expectedBehavior=expectedBehavior;
  this.cohort=cohort;
  this.reviewer=reviewer;
  this.evidenceRef=evidenceRef;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("fixture_id",fixtureId);
  values.put("rule_id",ruleId);
  values.put("fixture_ref",fixtureRef);
  values.put("fixture_hash",fixtureHash);
  values.put("expected_behavior",expectedBehavior);
  values.put("cohort",cohort);
  values.put("reviewer",reviewer);
  values.put("evidence_ref",evidenceRef);
  values.put("created_at",createdAt);
  return values;
 }
}

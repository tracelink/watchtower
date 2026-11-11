package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_definition_versions")
public class RuleDefinitionVersionEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="version_id", nullable=false, length=36)
 public String versionId;
 @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @Column(name="revision", nullable=false, length=64)
 public String revision;
 @Column(name="definition_hash", nullable=false, length=64)
 public String definitionHash;
 @Column(name="module", nullable=false, length=64)
 public String module;
 @Column(name="definition_json", nullable=false, columnDefinition="LONGTEXT")
 public String definitionJson;
 @Column(name="actor", nullable=false, length=255)
 public String actor;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 public RuleDefinitionVersionEntity() { }
 public RuleDefinitionVersionEntity(String versionId, Long ruleId, String revision, String definitionHash, String module, String definitionJson, String actor, Long createdAt) {
  this.versionId=versionId;
  this.ruleId=ruleId;
  this.revision=revision;
  this.definitionHash=definitionHash;
  this.module=module;
  this.definitionJson=definitionJson;
  this.actor=actor;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("version_id",versionId);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("definition_hash",definitionHash);
  values.put("module",module);
  values.put("definition_json",definitionJson);
  values.put("actor",actor);
  values.put("created_at",createdAt);
  return values;
 }
}

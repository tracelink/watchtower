package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="bypass_finding_identity")
@IdClass(BypassFindingIdentityEntity.Id.class)
public class BypassFindingIdentityEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="bypass_id", nullable=false)
 public Long bypassId;
 @jakarta.persistence.Id @Column(name="finding_id", nullable=false)
 public Long findingId;
 @Column(name="rule_id", nullable=true)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="effective_blocking", nullable=true)
 public Boolean effectiveBlocking;
 public BypassFindingIdentityEntity() { }
 public BypassFindingIdentityEntity(Long bypassId, Long findingId, Long ruleId, String revision, Boolean effectiveBlocking) {
  this.bypassId=bypassId;
  this.findingId=findingId;
  this.ruleId=ruleId;
  this.revision=revision;
  this.effectiveBlocking=effectiveBlocking;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("bypass_id",bypassId);
  values.put("finding_id",findingId);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("effective_blocking",effectiveBlocking);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public Long bypassId;
  public Long findingId;
  public Id() { }
  public Id(Long bypassId, Long findingId) {
   this.bypassId=bypassId;
   this.findingId=findingId;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(bypassId,id.bypassId) && Objects.equals(findingId,id.findingId); }
  @Override public int hashCode() { return Objects.hash(bypassId,findingId); }
 }
}

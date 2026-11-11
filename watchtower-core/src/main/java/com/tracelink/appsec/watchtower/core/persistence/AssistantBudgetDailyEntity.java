package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_budget_daily")
@IdClass(AssistantBudgetDailyEntity.Id.class)
public class AssistantBudgetDailyEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scope_key", nullable=false, length=64)
 public String scopeKey;
 @jakarta.persistence.Id @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @Column(name="charged_tokens", nullable=false)
 public Long chargedTokens;
 @Column(name="charged_cost_micros", nullable=false)
 public Long chargedCostMicros;
 public AssistantBudgetDailyEntity() { }
 public AssistantBudgetDailyEntity(String scopeKey, Long bucketStart, Long chargedTokens, Long chargedCostMicros) {
  this.scopeKey=scopeKey;
  this.bucketStart=bucketStart;
  this.chargedTokens=chargedTokens;
  this.chargedCostMicros=chargedCostMicros;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scope_key",scopeKey);
  values.put("bucket_start",bucketStart);
  values.put("charged_tokens",chargedTokens);
  values.put("charged_cost_micros",chargedCostMicros);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scopeKey;
  public Long bucketStart;
  public Id() { }
  public Id(String scopeKey, Long bucketStart) {
   this.scopeKey=scopeKey;
   this.bucketStart=bucketStart;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scopeKey,id.scopeKey) && Objects.equals(bucketStart,id.bucketStart); }
  @Override public int hashCode() { return Objects.hash(scopeKey,bucketStart); }
 }
}

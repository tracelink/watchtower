package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_request_reservations")
public class AssistantRequestReservationEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="reservation_id", nullable=false, length=36)
 public String reservationId;
 @Column(name="turn_id", nullable=false, length=36)
 public String turnId;
 @Column(name="owner_scope", nullable=false, length=64)
 public String ownerScope;
 @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @Column(name="reserved_tokens", nullable=false)
 public Long reservedTokens;
 @Column(name="reserved_cost_micros", nullable=false)
 public Long reservedCostMicros;
 @Column(name="actual_tokens", nullable=true)
 public Long actualTokens;
 @Column(name="actual_cost_micros", nullable=true)
 public Long actualCostMicros;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 /** The AI feature slice this reservation also charged, or null for chat. */
 @Column(name="feature", nullable=true, length=32)
 public String feature;
 public AssistantRequestReservationEntity() { }
 public AssistantRequestReservationEntity(String reservationId, String turnId, String ownerScope, Long bucketStart, Long reservedTokens, Long reservedCostMicros, Long actualTokens, Long actualCostMicros, Long createdAt, String feature) {
  this(reservationId,turnId,ownerScope,bucketStart,reservedTokens,reservedCostMicros,actualTokens,actualCostMicros,createdAt);
  this.feature=feature;
 }
 public AssistantRequestReservationEntity(String reservationId, String turnId, String ownerScope, Long bucketStart, Long reservedTokens, Long reservedCostMicros, Long actualTokens, Long actualCostMicros, Long createdAt) {
  this.reservationId=reservationId;
  this.turnId=turnId;
  this.ownerScope=ownerScope;
  this.bucketStart=bucketStart;
  this.reservedTokens=reservedTokens;
  this.reservedCostMicros=reservedCostMicros;
  this.actualTokens=actualTokens;
  this.actualCostMicros=actualCostMicros;
  this.createdAt=createdAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("reservation_id",reservationId);
  values.put("turn_id",turnId);
  values.put("owner_scope",ownerScope);
  values.put("bucket_start",bucketStart);
  values.put("reserved_tokens",reservedTokens);
  values.put("reserved_cost_micros",reservedCostMicros);
  values.put("actual_tokens",actualTokens);
  values.put("actual_cost_micros",actualCostMicros);
  values.put("created_at",createdAt);
  values.put("feature",feature);
  return values;
 }
}

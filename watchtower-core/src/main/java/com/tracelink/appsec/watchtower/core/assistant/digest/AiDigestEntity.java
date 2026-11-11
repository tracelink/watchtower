package com.tracelink.appsec.watchtower.core.assistant.digest;

import jakarta.persistence.*;

/** One weekly Home digest: the aggregate counts it was written from and the short lines about them. Counts only. */
@Entity
@Table(name="ai_digest",uniqueConstraints=@UniqueConstraint(columnNames={"schedule_key"}))
public class AiDigestEntity {
 @Id @Column(name="digest_id",length=36) public String id;
 @Column(name="schedule_key",length=10) public String scheduleKey;
 @Column(name="trigger_type",nullable=false,length=10) public String triggerType;
 @Column(name="created_by",nullable=false) public String createdBy;
 @Column(name="created_at",nullable=false) public long createdAt;
 @Column(nullable=false,length=12) public String status;
 @Column(name="window_start",nullable=false) public long windowStart;
 @Column(name="window_end",nullable=false) public long windowEnd;
 @Lob @Column(name="counts_json",nullable=false,columnDefinition="LONGTEXT") public String countsJson;
 @Lob @Column(name="points_json",columnDefinition="LONGTEXT") public String pointsJson;
 @Column(length=128) public String model;
 protected AiDigestEntity() { }
 public AiDigestEntity(String id,String scheduleKey,String triggerType,String createdBy,long createdAt,String status,long windowStart,long windowEnd,String countsJson,String pointsJson,String model) {
  this.id=id;this.scheduleKey=scheduleKey;this.triggerType=triggerType;this.createdBy=createdBy;this.createdAt=createdAt;this.status=status;
  this.windowStart=windowStart;this.windowEnd=windowEnd;this.countsJson=countsJson;this.pointsJson=pointsJson;this.model=model;
 }
}

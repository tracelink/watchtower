package com.tracelink.appsec.watchtower.core.rule.report;

import jakarta.persistence.*;

/** Immutable, source-free report snapshot. Scheduled reports carry a unique ISO-week period key. */
@Entity
@Table(name="rule_review_reports")
public class RuleReviewReportEntity {
 @Id @Column(name="report_id", length=36) private String reportId;
 @Column(name="period_key", length=16) private String periodKey;
 @Column(name="trigger_type", length=16, nullable=false) private String triggerType;
 @Column(name="actor", nullable=false) private String actor;
 @Column(name="settings_version", nullable=false) private long settingsVersion;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="summary_json", nullable=false, columnDefinition="LONGTEXT") private String summaryJson;
 @Column(name="item_schema",nullable=false) private int itemSchema;
 protected RuleReviewReportEntity() { }
 public RuleReviewReportEntity(String reportId,String periodKey,String triggerType,String actor,long settingsVersion,long createdAt,String summaryJson){
  this.reportId=reportId;this.periodKey=periodKey;this.triggerType=triggerType;this.actor=actor;this.settingsVersion=settingsVersion;this.createdAt=createdAt;this.summaryJson=summaryJson;
 }
 public String getReportId(){return reportId;}
 public String getPeriodKey(){return periodKey;}
 public String getTriggerType(){return triggerType;}
 public String getActor(){return actor;}
 public long getSettingsVersion(){return settingsVersion;}
 public long getCreatedAt(){return createdAt;}
 public String getSummaryJson(){return summaryJson;}
 public int getItemSchema(){return itemSchema;}
 public void withCompleteItems(){itemSchema=1;}
}

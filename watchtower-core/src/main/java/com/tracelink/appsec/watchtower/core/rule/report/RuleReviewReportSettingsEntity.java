package com.tracelink.appsec.watchtower.core.rule.report;

import jakarta.persistence.*;

/** Single shared row: whether the weekly review report runs, and on which ISO weekday (UTC). */
@Entity
@Table(name="rule_review_report_settings")
public class RuleReviewReportSettingsEntity {
 public static final int ID=1;
 @Id @Column(name="settings_id") private int id;
 @Column(name="enabled") private boolean enabled;
 @Column(name="weekday") private int weekday;
 @Version @Column(name="version") private long version;
 @Column(name="updated_by") private String updatedBy;
 @Column(name="updated_at") private long updatedAt;
 protected RuleReviewReportSettingsEntity() { }
 public boolean isEnabled(){return enabled;}
 public int getWeekday(){return weekday;}
 public long getVersion(){return version;}
 public String getUpdatedBy(){return updatedBy;}
 public long getUpdatedAt(){return updatedAt;}
 public void change(boolean enabled,int weekday,String actor,long now){this.enabled=enabled;this.weekday=weekday;this.updatedBy=actor;this.updatedAt=now;}
}

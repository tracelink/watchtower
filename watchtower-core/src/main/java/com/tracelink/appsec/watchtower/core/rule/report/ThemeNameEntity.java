package com.tracelink.appsec.watchtower.core.rule.report;

import jakarta.persistence.*;

/** One AI suggestion for a feedback theme (plan R5.2b); never feedback text or source. */
@Entity
@Table(name="rule_review_theme_names")
public class ThemeNameEntity {
 public static final String NAMED="NAMED",REJECTED="REJECTED";
 @Id @Column(name="name_key", length=64) private String nameKey;
 @Column(name="theme_fingerprint", length=64, nullable=false) private String themeFingerprint;
 @Column(name="rule_id", nullable=false) private long ruleId;
 @Column(name="status", length=16, nullable=false) private String status;
 @Column(name="name", length=60) private String name;
 @Column(name="cause", length=40) private String cause;
 @Column(name="explanation", length=255) private String explanation;
 @Column(name="model", length=128, nullable=false) private String model;
 @Column(name="effort", length=16, nullable=false) private String effort;
 @Column(name="prompt_version", length=16, nullable=false) private String promptVersion;
 @Column(name="text_sent", nullable=false) private boolean textSent;
 @Column(name="input_tokens", nullable=false) private long inputTokens;
 @Column(name="output_tokens", nullable=false) private long outputTokens;
 @Column(name="cost_micros", nullable=false) private long costMicros;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="last_used_at", nullable=false) private long lastUsedAt;
 protected ThemeNameEntity() { }
 /** What was asked: which theme, with which model, and whether record text was included. */
 public record Request(String nameKey,String fingerprint,long ruleId,String model,String effort,String promptVersion,boolean textSent) { }
 /** What came back and what it cost; name, cause and explanation are null when rejected. */
 public record Outcome(String status,String name,String cause,String explanation,long inputTokens,long outputTokens,long costMicros) { }
 public ThemeNameEntity(Request request,Outcome outcome,long now){
  nameKey=request.nameKey();themeFingerprint=request.fingerprint();ruleId=request.ruleId();model=request.model();effort=request.effort();promptVersion=request.promptVersion();textSent=request.textSent();
  status=outcome.status();name=outcome.name();cause=outcome.cause();explanation=outcome.explanation();inputTokens=outcome.inputTokens();outputTokens=outcome.outputTokens();costMicros=outcome.costMicros();
  createdAt=now;lastUsedAt=now;
 }
 public String getNameKey(){return nameKey;}
 public String getThemeFingerprint(){return themeFingerprint;}
 public long getRuleId(){return ruleId;}
 public String getStatus(){return status;}
 public String getName(){return name;}
 public String getCause(){return cause;}
 public String getExplanation(){return explanation;}
 public String getModel(){return model;}
 public String getEffort(){return effort;}
 public boolean isTextSent(){return textSent;}
 public long getCostMicros(){return costMicros;}
 public long getCreatedAt(){return createdAt;}
 public long getLastUsedAt(){return lastUsedAt;}
}

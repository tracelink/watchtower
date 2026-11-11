package com.tracelink.appsec.watchtower.core.assistant.assessment;

import jakarta.persistence.*;

/** One advisory AI answer for a finding occurrence (plan R6); never source code. */
@Entity
@Table(name="finding_assessments")
public class FindingAssessmentEntity {
 public static final String ASSESSED="ASSESSED",REJECTED="REJECTED";
 @Id @Column(name="assessment_id", length=36) private String assessmentId;
 @Column(name="occurrence_key", length=64, nullable=false) private String occurrenceKey;
 @Column(name="scan_type", length=16, nullable=false) private String scanType;
 @Column(name="scan_id", nullable=false) private long scanId;
 @Column(name="finding_key", length=64, nullable=false) private String findingKey;
 @Column(name="rule_id") private Long ruleId;
 @Column(name="rule_revision", length=64) private String ruleRevision;
 @Column(name="status", length=16, nullable=false) private String status;
 @Column(name="verdict", length=32) private String verdict;
 @Column(name="criteria_json", length=2048) private String criteriaJson;
 @Column(name="cited_lines", length=256) private String citedLines;
 @Column(name="knowledge_ids", length=512) private String knowledgeIds;
 @Column(name="model", length=128, nullable=false) private String model;
 @Column(name="effort", length=16, nullable=false) private String effort;
 @Column(name="prompt_version", length=16, nullable=false) private String promptVersion;
 @Column(name="input_tokens", nullable=false) private long inputTokens;
 @Column(name="output_tokens", nullable=false) private long outputTokens;
 @Column(name="cost_micros", nullable=false) private long costMicros;
 @Column(name="requested_by", nullable=false) private String requestedBy;
 @Column(name="created_at", nullable=false) private long createdAt;
 protected FindingAssessmentEntity() { }
 /** Which finding, at which rule revision, asked with which model, by whom. */
 public record Subject(String occurrenceKey,String scanType,long scanId,String findingKey,Long ruleId,String ruleRevision,String model,String effort,String promptVersion,String requestedBy) { }
 /** The validated answer (fields null when rejected) and its usage. */
 public record Answer(String status,String verdict,String criteriaJson,String citedLines,String knowledgeIds,long inputTokens,long outputTokens,long costMicros) { }
 public FindingAssessmentEntity(String id,Subject s,Answer a,long now){
  assessmentId=id;occurrenceKey=s.occurrenceKey();scanType=s.scanType();scanId=s.scanId();findingKey=s.findingKey();ruleId=s.ruleId();ruleRevision=s.ruleRevision();
  model=s.model();effort=s.effort();promptVersion=s.promptVersion();requestedBy=s.requestedBy();
  status=a.status();verdict=a.verdict();criteriaJson=a.criteriaJson();citedLines=a.citedLines();knowledgeIds=a.knowledgeIds();
  inputTokens=a.inputTokens();outputTokens=a.outputTokens();costMicros=a.costMicros();createdAt=now;
 }
 public String getAssessmentId(){return assessmentId;}
 public String getOccurrenceKey(){return occurrenceKey;}
 public Long getRuleId(){return ruleId;}
 public String getRuleRevision(){return ruleRevision;}
 public String getStatus(){return status;}
 public String getVerdict(){return verdict;}
 public String getCriteriaJson(){return criteriaJson;}
 public String getCitedLines(){return citedLines;}
 public String getKnowledgeIds(){return knowledgeIds;}
 public String getModel(){return model;}
 public String getEffort(){return effort;}
 public String getPromptVersion(){return promptVersion;}
 public long getCostMicros(){return costMicros;}
 public String getRequestedBy(){return requestedBy;}
 public long getCreatedAt(){return createdAt;}
}

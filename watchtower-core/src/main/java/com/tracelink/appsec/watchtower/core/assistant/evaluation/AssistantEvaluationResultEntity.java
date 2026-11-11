package com.tracelink.appsec.watchtower.core.assistant.evaluation;

import jakarta.persistence.*;

/** One question's outcome: turn reference, automatic checks and the engineer's score (no answer text). */
@Entity
@Table(name="assistant_evaluation_results")
public class AssistantEvaluationResultEntity {
 @Id @Column(name="result_id", length=36) private String resultId;
 @Column(name="run_id", nullable=false, length=36) private String runId;
 @Column(name="position", nullable=false) private int position;
 @Column(name="case_id", nullable=false, length=64) private String caseId;
 @Column(name="category", nullable=false, length=32) private String category;
 @Column(name="prompt_hash", nullable=false, length=64) private String promptHash;
 @Column(name="spec_json", nullable=false, columnDefinition="TEXT") private String specJson;
 @Column(name="session_id", length=36) private String sessionId;
 @Column(name="turn_id", length=36) private String turnId;
 @Column(name="status", nullable=false, length=16) private String status;
 @Column(name="error_code", length=64) private String errorCode;
 @Column(name="checks_json", columnDefinition="TEXT") private String checksJson;
 @Column(name="auto_passed") private Boolean autoPassed;
 @Column(name="tokens", nullable=false) private long tokens;
 @Column(name="cost_micros", nullable=false) private long costMicros;
 @Column(name="latency_ms") private Long latencyMs;
 @Column(name="score") private Integer score;
 @Column(name="reviewer") private String reviewer;
 @Column(name="note", length=300) private String note;
 @Column(name="scored_at") private Long scoredAt;
 @Column(name="version", nullable=false) private long version;
 protected AssistantEvaluationResultEntity() { }
 public AssistantEvaluationResultEntity(String resultId,String runId,int position,String caseId,String category,String promptHash,String specJson){
  this.resultId=resultId;this.runId=runId;this.position=position;this.caseId=caseId;this.category=category;this.promptHash=promptHash;this.specJson=specJson;this.status="PENDING";
 }
 public String getResultId(){return resultId;}
 public String getRunId(){return runId;}
 public int getPosition(){return position;}
 public String getCaseId(){return caseId;}
 public String getCategory(){return category;}
 public String getPromptHash(){return promptHash;}
 public String getSpecJson(){return specJson;}
 public String getSessionId(){return sessionId;}
 public String getTurnId(){return turnId;}
 public String getStatus(){return status;}
 public String getErrorCode(){return errorCode;}
 public String getChecksJson(){return checksJson;}
 public Boolean getAutoPassed(){return autoPassed;}
 public long getTokens(){return tokens;}
 public long getCostMicros(){return costMicros;}
 public Long getLatencyMs(){return latencyMs;}
 public Integer getScore(){return score;}
 public String getReviewer(){return reviewer;}
 public String getNote(){return note;}
 public Long getScoredAt(){return scoredAt;}
 public long getVersion(){return version;}
}

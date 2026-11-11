package com.tracelink.appsec.watchtower.core.assistant.evaluation;

import jakarta.persistence.*;

/** One activation evaluation run: a fixed, versioned question set through the real chat pipeline. */
@Entity
@Table(name="assistant_evaluation_runs")
public class AssistantEvaluationRunEntity {
 @Id @Column(name="run_id", length=36) private String runId;
 @Column(name="cases_version", nullable=false, length=32) private String casesVersion;
 @Column(name="requested_by", nullable=false) private String requestedBy;
 @Column(name="model", nullable=false, length=128) private String model;
 @Column(name="effort", nullable=false, length=24) private String effort;
 @Column(name="status", nullable=false, length=16) private String status;
 @Column(name="case_count", nullable=false) private int caseCount;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="updated_at", nullable=false) private long updatedAt;
 @Column(name="finished_at") private Long finishedAt;
 protected AssistantEvaluationRunEntity() { }
 public AssistantEvaluationRunEntity(String runId,String casesVersion,String requestedBy,String model,String effort,int caseCount,long now){
  this.runId=runId;this.casesVersion=casesVersion;this.requestedBy=requestedBy;this.model=model;this.effort=effort;this.status="QUEUED";this.caseCount=caseCount;this.createdAt=now;this.updatedAt=now;
 }
 public String getRunId(){return runId;}
 public String getCasesVersion(){return casesVersion;}
 public String getRequestedBy(){return requestedBy;}
 public String getModel(){return model;}
 public String getEffort(){return effort;}
 public String getStatus(){return status;}
 public int getCaseCount(){return caseCount;}
 public long getCreatedAt(){return createdAt;}
 public long getUpdatedAt(){return updatedAt;}
 public Long getFinishedAt(){return finishedAt;}
}

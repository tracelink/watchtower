package com.tracelink.appsec.watchtower.core.assistant.batch;

import jakarta.persistence.*;

/** One batch triage of one scan; at most one per scan, so asking again resumes it. Holds counts only. */
@Entity
@Table(name="ai_batch_run")
public class AiBatchRunEntity {
 public static final String QUEUED="QUEUED",RUNNING="RUNNING",DONE="DONE",PARTIAL_BUDGET="PARTIAL_BUDGET",FAILED="FAILED";
 @Id @Column(name="run_id", length=36) private String runId;
 @Column(name="scan_type", length=16, nullable=false) private String scanType;
 @Column(name="scan_id", nullable=false) private long scanId;
 @Column(name="requested_by", nullable=false) private String requestedBy;
 @Column(name="status", length=16, nullable=false) private String status;
 @Column(name="total", nullable=false) private int total;
 @Column(name="done", nullable=false) private int done;
 @Column(name="blocked", nullable=false) private int blocked;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="finished_at") private Long finishedAt;
 protected AiBatchRunEntity() { }
 public AiBatchRunEntity(String runId,String scanType,long scanId,String requestedBy,int total,int blocked,long now){
  this.runId=runId;this.scanType=scanType;this.scanId=scanId;this.requestedBy=requestedBy;this.status=QUEUED;this.total=total;this.blocked=blocked;this.createdAt=now;
 }
 public String getRunId(){return runId;}
 public String getScanType(){return scanType;}
 public long getScanId(){return scanId;}
 public String getRequestedBy(){return requestedBy;}
 public String getStatus(){return status;}
 public int getTotal(){return total;}
 public int getDone(){return done;}
 public int getBlocked(){return blocked;}
 public long getCreatedAt(){return createdAt;}
 public Long getFinishedAt(){return finishedAt;}
 public void setStatus(String status,Long finishedAt){this.status=status;this.finishedAt=finishedAt;}
 public void setDone(int done){this.done=done;}
 public void setRequestedBy(String requestedBy){this.requestedBy=requestedBy;}
}

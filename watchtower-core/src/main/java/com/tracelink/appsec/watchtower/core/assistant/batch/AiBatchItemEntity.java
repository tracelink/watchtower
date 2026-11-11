package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.io.Serializable;
import java.util.Objects;
import jakarta.persistence.*;

/** One finding of a batch triage and what became of it. */
@Entity
@Table(name="ai_batch_item")
@IdClass(AiBatchItemEntity.Key.class)
public class AiBatchItemEntity {
 /** BLOCKED_SECRET: a secret finding. BLOCKED_UNKNOWN: the rule behind the finding was never recorded, so it cannot be told from a secret and is withheld too. NO_EVIDENCE: no evidence could be gathered (for example the commit or its source could not be read), so the model was never asked. NO_ANSWER: the model was asked, or the feature was not ready, and no usable answer came back. */
 public static final String PENDING="PENDING",DONE="DONE",BLOCKED_SECRET="BLOCKED_SECRET",BLOCKED_UNKNOWN="BLOCKED_UNKNOWN",NO_ANSWER="NO_ANSWER",NO_EVIDENCE="NO_EVIDENCE";
 @Id @Column(name="run_id", length=36) private String runId;
 @Id @Column(name="finding_key", length=64) private String findingKey;
 @Column(name="status", length=20, nullable=false) private String status;
 @Column(name="assessment_id", length=36) private String assessmentId;
 protected AiBatchItemEntity() { }
 public AiBatchItemEntity(String runId,String findingKey,String status){this.runId=runId;this.findingKey=findingKey;this.status=status;}
 public String getRunId(){return runId;}
 public String getFindingKey(){return findingKey;}
 public String getStatus(){return status;}
 public String getAssessmentId(){return assessmentId;}
 public void finish(String status,String assessmentId){this.status=status;this.assessmentId=assessmentId;}
 public static class Key implements Serializable {
  private static final long serialVersionUID=1L;
  private String runId;private String findingKey;
  public Key() { }
  public Key(String runId,String findingKey){this.runId=runId;this.findingKey=findingKey;}
  @Override public boolean equals(Object o){return o instanceof Key k&&Objects.equals(runId,k.runId)&&Objects.equals(findingKey,k.findingKey);}
  @Override public int hashCode(){return Objects.hash(runId,findingKey);}
 }
}

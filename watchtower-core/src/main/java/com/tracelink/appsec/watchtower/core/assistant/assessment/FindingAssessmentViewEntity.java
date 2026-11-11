package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.io.Serializable;
import java.util.Objects;
import jakarta.persistence.*;

/** When a person first saw an assessment; agreement counts only judgments made before that. */
@Entity
@Table(name="finding_assessment_views")
@IdClass(FindingAssessmentViewEntity.Key.class)
public class FindingAssessmentViewEntity {
 @Id @Column(name="assessment_id", length=36) private String assessmentId;
 @Id @Column(name="viewer") private String viewer;
 @Column(name="first_viewed_at", nullable=false) private long firstViewedAt;
 protected FindingAssessmentViewEntity() { }
 public FindingAssessmentViewEntity(String assessmentId,String viewer,long firstViewedAt){this.assessmentId=assessmentId;this.viewer=viewer;this.firstViewedAt=firstViewedAt;}
 public String getAssessmentId(){return assessmentId;}
 public String getViewer(){return viewer;}
 public long getFirstViewedAt(){return firstViewedAt;}
 public static class Key implements Serializable {
  private static final long serialVersionUID=1L;
  private String assessmentId;private String viewer;
  public Key() { }
  public Key(String assessmentId,String viewer){this.assessmentId=assessmentId;this.viewer=viewer;}
  @Override public boolean equals(Object o){return o instanceof Key k&&Objects.equals(assessmentId,k.assessmentId)&&Objects.equals(viewer,k.viewer);}
  @Override public int hashCode(){return Objects.hash(assessmentId,viewer);}
 }
}

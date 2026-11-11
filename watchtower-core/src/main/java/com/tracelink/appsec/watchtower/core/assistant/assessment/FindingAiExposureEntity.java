package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.io.Serializable;
import java.util.Objects;
import jakarta.persistence.*;

/** The first time a person saw an AI opinion about a finding; never source code. */
@Entity
@Table(name="finding_ai_exposure")
@IdClass(FindingAiExposureEntity.Key.class)
public class FindingAiExposureEntity {
 @Id @Column(name="occurrence_key", length=64) private String occurrenceKey;
 @Id @Column(name="viewer") private String viewer;
 @Column(name="source", length=16, nullable=false) private String source;
 @Column(name="first_seen_at", nullable=false) private long firstSeenAt;
 protected FindingAiExposureEntity() { }
 public FindingAiExposureEntity(String occurrenceKey,String viewer,String source,long firstSeenAt){this.occurrenceKey=occurrenceKey;this.viewer=viewer;this.source=source;this.firstSeenAt=firstSeenAt;}
 public String getOccurrenceKey(){return occurrenceKey;}
 public String getViewer(){return viewer;}
 public String getSource(){return source;}
 public long getFirstSeenAt(){return firstSeenAt;}
 public static class Key implements Serializable {
  private static final long serialVersionUID=1L;
  private String occurrenceKey;private String viewer;
  public Key() { }
  public Key(String occurrenceKey,String viewer){this.occurrenceKey=occurrenceKey;this.viewer=viewer;}
  @Override public boolean equals(Object o){return o instanceof Key k&&Objects.equals(occurrenceKey,k.occurrenceKey)&&Objects.equals(viewer,k.viewer);}
  @Override public int hashCode(){return Objects.hash(occurrenceKey,viewer);}
 }
}

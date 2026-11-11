package com.tracelink.appsec.watchtower.core.rule.variant;

import jakarta.persistence.*;

/** One repository in a variant search: pinned commit, status and bounded locations only. */
@Entity
@Table(name="variant_search_repositories")
public class VariantSearchRepositoryEntity {
 @Id @Column(name="entry_id", length=36) private String entryId;
 @Column(name="search_id", nullable=false, length=36) private String searchId;
 @Column(name="position", nullable=false) private int position;
 @Column(name="repository_id", nullable=false) private long repositoryId;
 @Column(name="repository_name", nullable=false) private String repositoryName;
 @Column(name="api_label", nullable=false) private String apiLabel;
 @Column(name="commit_hash", length=40) private String commitHash;
 @Column(name="status", nullable=false) private String status;
 @Column(name="match_count", nullable=false) private int matchCount;
 @Column(name="truncated", nullable=false) private boolean truncated;
 @Column(name="error_code") private String errorCode;
 /** SHA-256 of the engine/runtime identity that produced the result, for later audit. */
 @Column(name="engine_identity", length=64) private String engineIdentity;
 @Column(name="claimed_at") private Long claimedAt;
 @Column(name="locations_json", columnDefinition="LONGTEXT") private String locationsJson;
 @Column(name="finished_at") private Long finishedAt;
 protected VariantSearchRepositoryEntity() { }
 public VariantSearchRepositoryEntity(String entryId,String searchId,int position,long repositoryId,String repositoryName,String apiLabel){
  this.entryId=entryId;this.searchId=searchId;this.position=position;this.repositoryId=repositoryId;this.repositoryName=repositoryName;this.apiLabel=apiLabel;this.status="PENDING";
 }
 public String getEntryId(){return entryId;}
 public String getSearchId(){return searchId;}
 public int getPosition(){return position;}
 public long getRepositoryId(){return repositoryId;}
 public String getRepositoryName(){return repositoryName;}
 public String getApiLabel(){return apiLabel;}
 public String getCommitHash(){return commitHash;}
 public String getStatus(){return status;}
 public int getMatchCount(){return matchCount;}
 public boolean isTruncated(){return truncated;}
 public String getErrorCode(){return errorCode;}
 public String getEngineIdentity(){return engineIdentity;}
 public String getLocationsJson(){return locationsJson;}
 public Long getFinishedAt(){return finishedAt;}
}

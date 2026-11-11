package com.tracelink.appsec.watchtower.core.rule.upstream;

import jakarta.persistence.*;

/** One detected change to a module's provided catalog, with its hold approval and test check. */
@Entity
@Table(name="upstream_updates")
public class UpstreamUpdateEntity {
 @Id @Column(name="update_id", length=36) private String updateId;
 @Column(name="module", nullable=false, length=100) private String module;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="added_json", nullable=false, columnDefinition="LONGTEXT") private String addedJson;
 @Column(name="changed_json", nullable=false, columnDefinition="LONGTEXT") private String changedJson;
 @Column(name="removed_json", nullable=false, columnDefinition="LONGTEXT") private String removedJson;
 @Column(name="held_count", nullable=false) private int heldCount;
 @Column(name="check_status", nullable=false, length=24) private String checkStatus;
 @Column(name="check_json", columnDefinition="LONGTEXT") private String checkJson;
 @Column(name="approved_by") private String approvedBy;
 @Column(name="approved_at") private Long approvedAt;
 @Column(name="version", nullable=false) private long version;
 protected UpstreamUpdateEntity() { }
 public UpstreamUpdateEntity(String updateId,String module,long createdAt,String addedJson,String changedJson,String removedJson,int heldCount,String checkStatus){
  this.updateId=updateId;this.module=module;this.createdAt=createdAt;this.addedJson=addedJson;this.changedJson=changedJson;this.removedJson=removedJson;this.heldCount=heldCount;this.checkStatus=checkStatus;
 }
 public String getUpdateId(){return updateId;}
 public String getModule(){return module;}
 public long getCreatedAt(){return createdAt;}
 public String getAddedJson(){return addedJson;}
 public String getChangedJson(){return changedJson;}
 public String getRemovedJson(){return removedJson;}
 public int getHeldCount(){return heldCount;}
 public String getCheckStatus(){return checkStatus;}
 public String getCheckJson(){return checkJson;}
 public String getApprovedBy(){return approvedBy;}
 public Long getApprovedAt(){return approvedAt;}
 public long getVersion(){return version;}
}

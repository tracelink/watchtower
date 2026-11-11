package com.tracelink.appsec.watchtower.core.rule.variant;

import jakarta.persistence.*;

/** One deterministic variant search: the exact definition run is stored so results stay explainable. */
@Entity
@Table(name="variant_searches")
public class VariantSearchEntity {
 @Id @Column(name="search_id", length=36) private String searchId;
 @Column(name="case_id", length=36) private String caseId;
 @Column(name="rule_id", nullable=false) private long ruleId;
 @Column(name="candidate_id", length=36) private String candidateId;
 @Column(name="module", nullable=false) private String module;
 @Column(name="designation", nullable=false) private String designation;
 @Column(name="definition_hash", nullable=false, length=64) private String definitionHash;
 @Column(name="definition_json", nullable=false, columnDefinition="LONGTEXT") private String definitionJson;
 @Column(name="requested_by", nullable=false) private String requestedBy;
 @Column(name="status", nullable=false) private String status;
 @Column(name="created_at", nullable=false) private long createdAt;
 @Column(name="updated_at", nullable=false) private long updatedAt;
 @Column(name="finished_at") private Long finishedAt;
 protected VariantSearchEntity() { }
 public VariantSearchEntity(String searchId,String caseId,long ruleId,String candidateId,String module,String designation,String definitionHash,String definitionJson,String requestedBy,long createdAt){
  this.searchId=searchId;this.caseId=caseId;this.ruleId=ruleId;this.candidateId=candidateId;this.module=module;this.designation=designation;
  this.definitionHash=definitionHash;this.definitionJson=definitionJson;this.requestedBy=requestedBy;this.status="QUEUED";this.createdAt=createdAt;this.updatedAt=createdAt;
 }
 public String getSearchId(){return searchId;}
 public String getCaseId(){return caseId;}
 public long getRuleId(){return ruleId;}
 public String getCandidateId(){return candidateId;}
 public String getModule(){return module;}
 public String getDesignation(){return designation;}
 public String getDefinitionHash(){return definitionHash;}
 public String getDefinitionJson(){return definitionJson;}
 public String getRequestedBy(){return requestedBy;}
 public String getStatus(){return status;}
 public long getCreatedAt(){return createdAt;}
 public long getUpdatedAt(){return updatedAt;}
 public Long getFinishedAt(){return finishedAt;}
}

package com.tracelink.appsec.watchtower.core.rule.knowledge;

import jakarta.persistence.*;

/**
 * One reviewed, scoped knowledge entry (plan R5.5). Scope lists and evidence are bounded JSON text;
 * the statement is short human prose, never source code. Status changes go through {@link #decide}.
 */
@Entity
@Table(name="assistant_knowledge")
public class KnowledgeEntity {
 @Id @Column(name="knowledge_id", length=36) private String knowledgeId;
 @Column(name="kind", length=24, nullable=false) private String kind;
 @Column(name="statement", length=300, nullable=false) private String statement;
 @Column(name="language", length=32, nullable=false) private String language;
 @Column(name="library", length=128, nullable=false) private String library;
 @Column(name="version_range", length=64, nullable=false) private String versionRange;
 @Column(name="all_repositories", nullable=false) private boolean allRepositories;
 @Column(name="repository_ids", length=1024, nullable=false) private String repositoryIds;
 @Column(name="rule_ids", length=1024, nullable=false) private String ruleIds;
 @Column(name="cwes", length=512, nullable=false) private String cwes;
 @Column(name="evidence_json", length=2048, nullable=false) private String evidenceJson;
 @Column(name="status", length=16, nullable=false) private String status;
 @Column(name="review_by", length=10, nullable=false) private String reviewBy;
 @Column(name="proposed_by", nullable=false) private String proposedBy;
 @Column(name="proposed_at", nullable=false) private long proposedAt;
 @Column(name="decided_by") private String decidedBy;
 @Column(name="decided_at") private Long decidedAt;
 @Column(name="decision_note", length=300) private String decisionNote;
 @Version @Column(name="version", nullable=false) private long version;
 protected KnowledgeEntity() { }
 /** The validated content of a proposal; lists are already JSON. */
 public record Content(String kind,String statement,String language,String library,String versionRange,boolean allRepositories,
   String repositoryIds,String ruleIds,String cwes,String evidenceJson,String reviewBy) { }
 public KnowledgeEntity(String id,Content c,String actor,long now){
  knowledgeId=id;kind=c.kind();statement=c.statement();language=c.language();library=c.library();versionRange=c.versionRange();
  allRepositories=c.allRepositories();repositoryIds=c.repositoryIds();ruleIds=c.ruleIds();cwes=c.cwes();evidenceJson=c.evidenceJson();reviewBy=c.reviewBy();
  status=KnowledgeService.PROPOSED;proposedBy=actor;proposedAt=now;
 }
 void decide(String newStatus,String actor,String note,long now){status=newStatus;decidedBy=actor;decidedAt=now;decisionNote=note;}
 public String getKnowledgeId(){return knowledgeId;}
 public String getKind(){return kind;}
 public String getStatement(){return statement;}
 public String getLanguage(){return language;}
 public String getLibrary(){return library;}
 public String getVersionRange(){return versionRange;}
 public boolean isAllRepositories(){return allRepositories;}
 public String getRepositoryIds(){return repositoryIds;}
 public String getRuleIds(){return ruleIds;}
 public String getCwes(){return cwes;}
 public String getEvidenceJson(){return evidenceJson;}
 public String getStatus(){return status;}
 public String getReviewBy(){return reviewBy;}
 public String getProposedBy(){return proposedBy;}
 public long getProposedAt(){return proposedAt;}
 public String getDecidedBy(){return decidedBy;}
 public Long getDecidedAt(){return decidedAt;}
 public String getDecisionNote(){return decisionNote;}
 public long getVersion(){return version;}
}

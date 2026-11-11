package com.tracelink.appsec.watchtower.core.rule.knowledge;

import jakarta.persistence.*;

/** Append-only record of who proposed, approved, rejected or retired a knowledge entry. */
@Entity
@Table(name="assistant_knowledge_audit")
public class KnowledgeAuditEntity {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) @Column(name="audit_id") private Long auditId;
 @Column(name="knowledge_id", length=36, nullable=false) private String knowledgeId;
 @Column(name="action", length=16, nullable=false) private String action;
 @Column(name="actor", nullable=false) private String actor;
 @Column(name="note", length=300) private String note;
 @Column(name="created_at", nullable=false) private long createdAt;
 protected KnowledgeAuditEntity() { }
 public KnowledgeAuditEntity(String knowledgeId,String action,String actor,String note,long createdAt){
  this.knowledgeId=knowledgeId;this.action=action;this.actor=actor;this.note=note;this.createdAt=createdAt;
 }
 public String getKnowledgeId(){return knowledgeId;}
 public String getAction(){return action;}
 public String getActor(){return actor;}
 public String getNote(){return note;}
 public long getCreatedAt(){return createdAt;}
}

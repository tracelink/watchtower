package com.tracelink.appsec.watchtower.core.rule.improvement;

import jakarta.persistence.*;

/** Shared candidate provenance excludes private conversation content and source excerpts. */
@Entity @Table(name="rule_candidate_provenance")
public class RuleCandidateProvenanceEntity {
 @Id @Column(name="candidate_id",length=36) public String candidateId;
 @Column(name="proposal_id",nullable=false,length=36,unique=true) public String proposalId;
 @Column(name="rule_id",nullable=false) public long ruleId;
 @Column(name="base_revision",nullable=false,length=64) public String baseRevision;
 @Column(name="evidence_hash",nullable=false,length=64) public String evidenceHash;
 @Column(nullable=false) public String actor;
 @Lob @Column(name="accepted_patch_json",nullable=false,columnDefinition="LONGTEXT") public String acceptedPatchJson;
 @Column(name="created_at",nullable=false) public long createdAt;
 protected RuleCandidateProvenanceEntity() { }
 public RuleCandidateProvenanceEntity(String id,RuleImprovementProposalEntity p,String actor,String patch){candidateId=id;proposalId=p.id;ruleId=p.ruleId;baseRevision=p.baseRevision;evidenceHash=p.evidenceHash;this.actor=actor;acceptedPatchJson=patch;createdAt=System.currentTimeMillis();}
}

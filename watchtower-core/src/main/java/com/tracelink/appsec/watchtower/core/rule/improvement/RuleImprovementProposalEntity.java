package com.tracelink.appsec.watchtower.core.rule.improvement;

import jakarta.persistence.*;

/** Durable source-free decision and evidence identities; raw evidence stays in transcript storage. */
@Entity @Table(name="rule_improvement_proposals",uniqueConstraints=@UniqueConstraint(columnNames={"owner","request_key"}))
public class RuleImprovementProposalEntity {
 @Id @Column(length=36) public String id;
 @Version public long version;
 @Column(nullable=false) public String owner;
 @Column(name="request_key",nullable=false,length=36) public String requestKey;
 @Column(name="rule_id",nullable=false) public long ruleId;
 @Column(name="base_revision",length=64) public String baseRevision;
 @Column(name="definition_hash",nullable=false,length=64) public String definitionHash;
 @Column(name="evidence_hash",nullable=false,length=64) public String evidenceHash;
 @Column(name="request_hash",nullable=false,length=64) public String requestHash;
 @Lob @Column(name="manifest_json",nullable=false,columnDefinition="LONGTEXT") public String manifestJson;
 @Column(name="turn_id",length=36) public String turnId;
 @Column(nullable=false,length=24) public String status;
 @Column(length=128) public String model;
 @Column(length=16) public String effort;
 @Column(name="prompt_version",nullable=false,length=32) public String promptVersion="improvement-v1";
 @Lob @Column(name="proposal_json",columnDefinition="LONGTEXT") public String proposalJson;
 @Column(name="created_at",nullable=false) public long createdAt;
 protected RuleImprovementProposalEntity() { }
 public RuleImprovementProposalEntity(String id,String owner,String key,RuleImprovementEvidence.Manifest m,String requestHash){this.id=id;this.owner=owner;requestKey=key;ruleId=m.ruleId();baseRevision=m.baseRevision();definitionHash=m.definitionHash();evidenceHash=RuleImprovementEvidence.hash(m);this.requestHash=requestHash;createdAt=System.currentTimeMillis();status="QUEUED";}
}

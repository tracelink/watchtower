package com.tracelink.appsec.watchtower.core.rule.upstream;

import java.io.Serializable;
import java.util.Objects;
import jakarta.persistence.*;

/** The last provided catalog seen for a module; the next sync diffs against it. */
@Entity
@Table(name="upstream_rule_snapshots")
public class UpstreamRuleSnapshotEntity {
 @Embeddable
 public static class Key implements Serializable {
  @Column(name="module", length=100) private String module;
  @Column(name="rule_name", length=255) private String ruleName;
  protected Key() { }
  public Key(String module,String ruleName){this.module=module;this.ruleName=ruleName;}
  public String getModule(){return module;}
  public String getRuleName(){return ruleName;}
  @Override public boolean equals(Object o){return o instanceof Key k&&Objects.equals(module,k.module)&&Objects.equals(ruleName,k.ruleName);}
  @Override public int hashCode(){return Objects.hash(module,ruleName);}
 }
 @EmbeddedId private Key key;
 @Column(name="rule_id", nullable=false) private long ruleId;
 @Column(name="revision", length=64) private String revision;
 protected UpstreamRuleSnapshotEntity() { }
 public UpstreamRuleSnapshotEntity(String module,String ruleName,long ruleId,String revision){this.key=new Key(module,ruleName);this.ruleId=ruleId;this.revision=revision;}
 public Key getKey(){return key;}
 public long getRuleId(){return ruleId;}
 public String getRevision(){return revision;}
}

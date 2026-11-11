package com.tracelink.appsec.watchtower.core.assistant.actions;

import java.util.*;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;

/** Only these domain operations can be prepared. There is deliberately no execution tool. */
public final class RulesetActions {
 private RulesetActions() { }
 public enum Type { CREATE, UPDATE, MEMBERSHIP, INHERIT, DEFAULT, DELETE, ASSIGN }
 /** Existing targets are decimal IDs; created targets use a preceding CREATE's local:reference. */
 public record Operation(Type type,String target,String name,String description,RulesetDesignation designation,
   RulePriority blockingLevel,List<Long> ruleIds,List<String> inherited,List<Long> repositoryIds) {
  public Operation { ruleIds=ruleIds==null?List.of():List.copyOf(ruleIds);inherited=inherited==null?List.of():List.copyOf(inherited);repositoryIds=repositoryIds==null?List.of():List.copyOf(repositoryIds); }
 }
 public record Request(String idempotencyKey,List<Operation> operations) { }
 public record Approval(long version,String contentHash,Map<String,String> deletionNames) { }
 public record Ruleset(String id,long version,String name,String description,RulesetDesignation designation,
   RulePriority blockingLevel,SortedSet<Long> direct,SortedSet<String> inherited) { }
 public record Repository(long id,long version,String name,String ruleset) { }
 public record Difference(String id,Ruleset before,Ruleset after,List<Long> effectiveAdded,List<Long> effectiveRemoved,
   List<Long> secretsCoverageRemoved,boolean blockingReduced) { }
 public record Assignment(Repository before,Repository after) { }
 public record Preview(List<Operation> operations,List<Difference> rulesets,List<Assignment> repositories,
   String dependencyHash,List<String> requiredPermissions,List<String> limitations) { }
 public record View(String id,long version,String status,String contentHash,long expiresAt,Preview preview,Object receipt) { }
}

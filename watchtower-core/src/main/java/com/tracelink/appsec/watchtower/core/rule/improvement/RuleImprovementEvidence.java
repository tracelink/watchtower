package com.tracelink.appsec.watchtower.core.rule.improvement;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;

/** Bounded mixed-judgment sampling; never reads fixture assets or held-out metadata/results. */
@Service
public class RuleImprovementEvidence {
 public record Reference(String id,String revision,String contentHash,Object data) { }
 /** {@code currentTotal} counts the records about the current rule revision; the rest are older or unknown. */
 public record Sample(String kind,String revisionScope,long total,int selected,boolean truncated,long currentTotal) { }
 public record Manifest(long ruleId,String baseRevision,int days,String definitionHash,Map<String,RuleCandidateWorkspace.Field> editableFields,
   boolean authoringAvailable,List<String> authoringReasons,List<Reference> references,List<Sample> samples,List<String> limitations) { }
 private final LedgerRepository records;private final RuleCandidateService candidates;private final AssistantAccess access;
 private final AssistantSecretFindings secrets;private final RuleHealthService health;private final KnowledgeService knowledge;
 public RuleImprovementEvidence(LedgerRepository records,RuleCandidateService candidates,AssistantAccess access,AssistantSecretFindings secrets,RuleHealthService health,KnowledgeService knowledge){this.records=records;this.candidates=candidates;this.access=access;this.secrets=secrets;this.health=health;this.knowledge=knowledge;}
 public void require(String owner){for(String grant:List.of("Assistant Use","Ruleset View","Scan Results View"))access.require(owner,grant);}
 @Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
 public Manifest gather(long ruleId,int days,String language,String owner){
  require(owner);if(!Set.of(7,30,90).contains(days))throw new IllegalArgumentException("Choose a 7, 30 or 90 day window");
  var active=candidates.current(ruleId).toDto();var workspace=candidates.workspace(ruleId);boolean sensitive=secrets.isSecretRule(active);
  long since=System.currentTimeMillis()-days*86400000L;var refs=new ArrayList<Reference>();var samples=new ArrayList<Sample>();
  // Restrict all prose about secret rules. Exact definitions are redacted again at the boundary.
  refs.add(reference("rule/"+ruleId,active.getRevision(),Map.of("definition",AssistantToolRegistry.redact(AssistantState.mapper().valueToTree(active)),"module",active.getModule())));
  refs.add(reference("health/"+ruleId,active.getRevision(),health.health(ruleId,active.getRevision(),days,"all")));
  for(String scope:List.of("CURRENT","HISTORICAL_OR_UNKNOWN"))for(String judgment:List.of("TRUE_POSITIVE","FALSE_POSITIVE","UNKNOWN")){
   String filter="f.ruleId=?1 AND f.occurredAt>=?2 AND f.judgment=?3 AND "+(scope.equals("CURRENT")?"f.revision=?4":"(f.revision<>?4 OR f.revision IS NULL)");
   long total=records.scalar(Long.class,"SELECT COUNT(f) FROM FindingFeedbackEntity f WHERE "+filter,ruleId,since,judgment,active.getRevision());
   var rows=records.list(FindingFeedbackEntity.class,"SELECT f FROM FindingFeedbackEntity f WHERE "+filter+" ORDER BY f.updatedAt DESC,f.occurrenceKey",0,4,ruleId,since,judgment,active.getRevision());
   for(var f:rows){var data=f.values();data.remove("reviewer");if(sensitive)data.put("explanation",AssistantSecretFindings.WITHHELD);refs.add(reference("feedback/"+f.occurrenceKey,f.revision,data));}
   samples.add(new Sample(judgment,scope,total,rows.size(),total>rows.size(),scope.equals("CURRENT")?total:0));
  }
  long reviewCount=records.scalar(Long.class,"SELECT COUNT(r) FROM RuleReviewItemEntity r WHERE r.ruleId=?1 AND r.updatedAt>=?2",ruleId,since);
  var reviews=records.list(RuleReviewItemEntity.class,"SELECT r FROM RuleReviewItemEntity r WHERE r.ruleId=?1 AND r.updatedAt>=?2 ORDER BY r.updatedAt DESC,r.reviewId",0,6,ruleId,since);
  for(var r:reviews){var data=new LinkedHashMap<String,Object>();data.put("version",r.version);data.put("status",r.status);data.put("reason",r.reason);data.put("recommendation",sensitive?AssistantSecretFindings.WITHHELD:r.recommendation);data.put("outcome",sensitive?AssistantSecretFindings.WITHHELD:r.outcome);refs.add(reference("review/"+r.reviewId,r.revision,data));}
  long currentReviews=records.scalar(Long.class,"SELECT COUNT(r) FROM RuleReviewItemEntity r WHERE r.ruleId=?1 AND r.updatedAt>=?2 AND r.revision=?3",ruleId,since,active.getRevision());
  samples.add(new Sample("SAVED_REVIEWS","MIXED",reviewCount,reviews.size(),reviewCount>reviews.size(),currentReviews));
  // Source-free miss metadata only; a miss is a human record, not a model-confirmed finding.
  long missCount=records.scalar(Long.class,"SELECT COUNT(m) FROM MissedVulnerabilityCaseEntity m WHERE m.ruleId=?1 AND m.createdAt>=?2",ruleId,since);
  var misses=records.list(MissedVulnerabilityCaseEntity.class,"SELECT m FROM MissedVulnerabilityCaseEntity m WHERE m.ruleId=?1 AND m.createdAt>=?2 ORDER BY m.createdAt DESC,m.caseId",0,4,ruleId,since);
  for(var m:misses)refs.add(reference("miss/"+m.caseId,m.revision,Map.of("cwe",m.cwe,"language",m.language,"framework",m.framework,"frameworkVersion",m.frameworkVersion,"createdAt",m.createdAt)));
  long currentMisses=records.scalar(Long.class,"SELECT COUNT(m) FROM MissedVulnerabilityCaseEntity m WHERE m.ruleId=?1 AND m.createdAt>=?2 AND m.revision=?3",ruleId,since,active.getRevision());
  samples.add(new Sample("MISSED_CASES","MIXED",missCount,misses.size(),missCount>misses.size(),currentMisses));
  if(language!=null&&!language.isBlank()&&!sensitive){for(var item:knowledge.applicable(ruleId,active.getStewardship().getCwe(),null,language)){String id=Objects.toString(item.get("id"),Objects.toString(item.get("knowledge_id"),""));refs.add(reference("knowledge/"+id,active.getRevision(),item));}}
  return new Manifest(ruleId,active.getRevision(),days,RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(active)),workspace.fieldMetadata(),workspace.authoringAvailable(),workspace.authoringReasons(),List.copyOf(refs),List.copyOf(samples),List.of("Samples are deterministic and bounded across human judgment categories. Disposition (including accepted risk) does not change judgment.","Historical or unknown-revision evidence does not describe the current rule revision.","No repository source code or held-out fixtures/results are supplied. Examples are illustrative and never executable evidence.","Assessment predictions are not confirmed human feedback. Sparse or conflicting evidence may require more review."));
 }
 static Reference reference(String id,String revision,Object data){var safe=AssistantToolRegistry.redact(AssistantState.mapper().valueToTree(data));return new Reference(id,revision,RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(safe)),AssistantState.mapper().convertValue(safe,Object.class));}
 public String safeQuestion(long ruleId,String question){return secrets.isSecretRule(candidates.current(ruleId).toDto())?AssistantSecretFindings.WITHHELD:AssistantText.redact(question);}
 /** Human decisions only: reviewed findings, saved reviews and missed cases (never AI opinions or knowledge). */
 public static boolean hasHumanEvidence(Manifest manifest){return manifest.samples().stream().anyMatch(sample->sample.total()>0);}
 public static String hash(Manifest manifest){return RuleDefinitionHistory.hash(RuleDefinitionHistory.encode(manifest));}
}

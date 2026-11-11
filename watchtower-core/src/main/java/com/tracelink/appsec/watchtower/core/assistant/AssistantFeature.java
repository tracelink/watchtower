package com.tracelink.appsec.watchtower.core.assistant;

import java.util.Arrays;
import java.util.Optional;

/**
 * The AI features an admin can switch on, and the budget slices they draw from. Each switchable
 * feature is off by default. A feature that does bulk or background work needs its own daily slice so
 * it cannot use up the budget that chat shares.
 */
public enum AssistantFeature {
 /** Chat knows which page the person is on. It uses the chat budget, so it needs no slice. */
 CONTEXT_CARDS("contextCards","Page context",true,false),
 BYPASS_SUMMARY("bypassSummary","Bypass summary",true,true),
 BATCH_TRIAGE("batchTriage","Batch triage",true,true),
 ONBOARDING("onboarding","Repository onboarding",true,true),
 JOB_DIAGNOSIS("jobDiagnosis","Failure diagnosis",true,true),
 MISSED_CASE("missedCase","Missed-vulnerability drafts",true,true),
 ALERT_COPILOT("alertCopilot","Alert-route copilot",true,true),
 HOME_DIGEST("homeDigest","Home digest",true,true),
 CWE_SUGGEST("cweSuggest","CWE suggestions",true,true),
 /** Chat can look CWEs up in the catalog stored in Watchtower. No model call of its own, so no slice. */
 CWE_REFERENCE("cweReference","CWE reference",true,false),
 /** Drafts a rule for a coverage gap and opens it, unsaved, in a designer. It has its own daily slice. */
 RULE_DRAFT("ruleDraft","Rule drafts",true,true),
 /** Reads files a person picked from a scan and lists weaknesses no scanner finding covers. Own daily slice. */
 AI_CODE_REVIEW("aiCodeReview","AI code review",true,true),
 /** Drafts the fields of a Knowledge proposal from the evidence a person chose. A second person still approves. Own daily slice. */
 KNOWLEDGE_DRAFT("knowledgeDraft","Knowledge drafts",true,true),
 /** Advisory finding assessment keeps its own switch; it only gets an optional slice. */
 FINDING_ASSESSMENT("findingAssessment","Finding assessment",false,false);

 private final String key,label;private final boolean switchable;private final boolean needsSlice;
 AssistantFeature(String key,String label,boolean switchable,boolean needsSlice){this.key=key;this.label=label;this.switchable=switchable;this.needsSlice=needsSlice;}
 /** Plain words for the admin page and the budget tooltip. */
 public String label(){return label;}
 /** The name used in stored settings and the admin page. */
 public String key(){return key;}
 /** Whether the {@code features.enabled} setting controls it. */
 public boolean isSwitchable(){return switchable;}
 /** Whether turning it on requires a daily slice. */
 public boolean needsSlice(){return needsSlice;}
 /** Whether an admin can give it a daily slice. */
 public boolean hasSlice(){return !switchable||needsSlice;}
 public static Optional<AssistantFeature> ofKey(String key){return Arrays.stream(values()).filter(f->f.key.equals(key)).findFirst();}
}

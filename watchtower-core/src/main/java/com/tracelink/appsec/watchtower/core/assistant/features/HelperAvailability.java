package com.tracelink.appsec.watchtower.core.assistant.features;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.assistant.*;

/**
 * Which AI helpers this person can use right now, so a page shows a helper only when it will work for
 * them: the feature is on and ready, and they hold the grants it needs. It asks nothing of the model.
 */
@Service
public class HelperAvailability {
 private final StructuredFeatureCall calls;private final AssistantAccess access;private final AssistantSettingsService settings;
 public HelperAvailability(StructuredFeatureCall calls,AssistantAccess access,AssistantSettingsService settings){this.calls=calls;this.access=access;this.settings=settings;}
 public Map<String,Boolean> of(String owner){
  var held=access.authorities(owner);var out=new LinkedHashMap<String,Boolean>();
  boolean assistant=held.contains("Assistant Use");
  out.put("draft",assistant&&settings.readiness().ready()&&settings.get().settings().isFeatureOn(AssistantFeature.CONTEXT_CARDS));
  out.put("bypass",assistant&&held.containsAll(java.util.Set.of("Scan Results View","PR Scan Bypass"))&&calls.readiness(AssistantFeature.BYPASS_SUMMARY).ready());
  out.put("diagnose",assistant&&held.contains("Scan Results View")&&calls.readiness(AssistantFeature.JOB_DIAGNOSIS).ready());
  out.put("triage",assistant&&held.containsAll(AssistantSourceTools.GRANTS)&&calls.readiness(AssistantFeature.BATCH_TRIAGE).ready());
  out.put("onboarding",assistant&&held.containsAll(OnboardingService.GRANTS)&&calls.readiness(AssistantFeature.ONBOARDING).ready());
  out.put("fixture",assistant&&held.containsAll(FixtureDraftService.GRANTS)&&calls.readiness(AssistantFeature.MISSED_CASE).ready());
  out.put("alerts",assistant&&held.containsAll(com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteChangeSetService.GRANTS)&&calls.readiness(AssistantFeature.ALERT_COPILOT).ready());
  out.put("cwe",assistant&&held.containsAll(CweSuggestService.GRANTS)&&calls.readiness(AssistantFeature.CWE_SUGGEST).ready());
  out.put("ruleDraft",assistant&&held.containsAll(RuleDraftSuggestService.GRANTS)&&calls.readiness(AssistantFeature.RULE_DRAFT).ready());
  out.put("aiReview",assistant&&held.containsAll(AssistantSourceTools.GRANTS)&&calls.readiness(AssistantFeature.AI_CODE_REVIEW).ready());
  out.put("knowledgeDraft",assistant&&held.containsAll(KnowledgeDraftService.GRANTS)&&calls.readiness(AssistantFeature.KNOWLEDGE_DRAFT).ready());
  return out;
 }
}

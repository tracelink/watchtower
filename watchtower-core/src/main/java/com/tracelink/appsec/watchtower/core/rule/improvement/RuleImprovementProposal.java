package com.tracelink.appsec.watchtower.core.rule.improvement;

import java.util.*;

/** Examples and suggested tests remain expiring transcript artifacts, never reviewed fixtures. */
public record RuleImprovementProposal(Outcome outcome,String problem,List<String> citations,Map<String,Object> changes,
 String expectedBenefit,List<String> regressions,List<String> limitations,List<String> examples,List<String> proposedTests) {
 public enum Outcome { PROPOSED_CHANGE, ADVICE_ONLY, NEEDS_MORE_EVIDENCE }
 public RuleImprovementProposal durable(){return new RuleImprovementProposal(outcome,problem,citations,changes,expectedBenefit,regressions,limitations,List.of(),List.of());}
}

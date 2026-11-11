package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.job.*;

/** Jobs carry an opaque run id only; run fencing is independent of the queue worker's lease. */
@Component
public class RuleCandidateTestJob implements AsyncJobHandler {
 private final RuleCandidateService candidates;private final AssistantAccess access;
 public RuleCandidateTestJob(RuleCandidateService candidates,AssistantAccess access){this.candidates=candidates;this.access=access;}
 @Override public AsyncJobType type(){return AsyncJobType.RULE_CANDIDATE_TEST;}
 @Override public String handle(AsyncJobEntity job,Consumer<String> progress) {
  String id=RuleCandidateService.uuid(job.getPayload());
  progress.accept("Comparing exact revisions against reviewed fixtures");
  candidates.run(id,()->access.require(job.getCreatedBy(),"Rule Modify"));return id;
 }
}

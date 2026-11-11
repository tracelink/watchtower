package com.tracelink.appsec.watchtower.core.assistant.evaluation;

import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Asks the evaluation questions one at a time on the shared job queue; resumable on any pod. */
@Component
public class AssistantEvaluationJob implements AsyncJobHandler {
 private final AssistantEvaluationService evaluations;
 public AssistantEvaluationJob(AssistantEvaluationService evaluations){this.evaluations=evaluations;}
 @Override public AsyncJobType type(){return AsyncJobType.ASSISTANT_EVALUATION;}
 @Override public String handle(AsyncJobEntity job,Consumer<String> progress){
  try{evaluations.run(job.getPayload(),progress);return null;}
  catch(com.tracelink.appsec.watchtower.core.job.RetryLaterException e){throw e;}
  catch(RuntimeException e){evaluations.finishRun(job.getPayload(),"FAILED");throw e;}
 }
}

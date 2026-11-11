package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Runs a batch triage on the shared job queue; any pod may run it, and a restarted run resumes. */
@Component
public class BatchTriageJob implements AsyncJobHandler {
 private final BatchTriageService triage;
 public BatchTriageJob(BatchTriageService triage){this.triage=triage;}
 @Override public AsyncJobType type(){return AsyncJobType.AI_BATCH_TRIAGE;}
 @Override public String handle(AsyncJobEntity job,Consumer<String> progress){return triage.run(job.getPayload(),progress);}
}

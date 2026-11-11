package com.tracelink.appsec.watchtower.core.rule.upstream;

import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Re-tests the changed rules of one upstream update against their reviewed fixtures. */
@Component
public class UpstreamCheckJob implements AsyncJobHandler {
 private final UpstreamSyncService sync;
 public UpstreamCheckJob(UpstreamSyncService sync){this.sync=sync;}
 @Override public AsyncJobType type(){return AsyncJobType.UPSTREAM_CHECK;}
 @Override public String handle(AsyncJobEntity job,Consumer<String> progress){
  try{sync.check(job.getPayload(),progress);return null;}
  catch(RuntimeException e){sync.setCheck(job.getPayload(),"UNAVAILABLE",null);throw e;}
 }
}

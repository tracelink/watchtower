package com.tracelink.appsec.watchtower.core.rule.variant;

import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Runs a variant search on the shared job queue, so any pod can pick it up and resume it. */
@Component
public class VariantSearchJob implements AsyncJobHandler {
 private final VariantSearchService searches;
 public VariantSearchJob(VariantSearchService searches){this.searches=searches;}
 @Override public AsyncJobType type(){return AsyncJobType.VARIANT_SEARCH;}
 @Override public String handle(AsyncJobEntity job,Consumer<String> progress){
  try{searches.run(job.getPayload(),progress);return null;}
  catch(RuntimeException e){searches.fail(job.getPayload(),"SEARCH_FAILED");throw e;}
 }
}

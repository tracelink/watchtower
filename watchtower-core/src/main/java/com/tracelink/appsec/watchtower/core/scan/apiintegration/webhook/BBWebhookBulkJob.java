package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Lazy;
import com.tracelink.appsec.watchtower.core.job.*;
@Component
public class BBWebhookBulkJob implements AsyncJobHandler {
 private final BBWebhookManagementService service;
 public BBWebhookBulkJob(@Lazy BBWebhookManagementService service){this.service=service;}
 public AsyncJobType type(){return AsyncJobType.WEBHOOK_BULK;}
 public String handle(AsyncJobEntity job,Consumer<String> progress){return service.run(job.getPayload(),progress);}
}

package com.tracelink.appsec.watchtower.core.assistant;

import java.nio.file.Path;
import java.io.IOException;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

@Configuration
public class AssistantConfiguration {
 @Bean public AssistantTranscriptStore assistantTranscriptStore(S3Service s3,
  @Value("${watchtower.assistant.transcript-dir:./assistant-transcripts}")String directory)throws IOException {
  if(s3.isEnabled())return new S3AssistantTranscriptStore(s3);
  // Chat is switched on in the UI, so startup cannot refuse; readiness reports missing shared storage instead.
  return new LocalAssistantTranscriptStore(Path.of(directory));
 }
}

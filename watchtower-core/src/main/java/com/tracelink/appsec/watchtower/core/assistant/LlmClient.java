package com.tracelink.appsec.watchtower.core.assistant;

import com.fasterxml.jackson.databind.node.*;
import java.io.IOException;

public interface LlmClient {
 record Request(String model,String effort,ArrayNode input,ArrayNode tools,int maxOutputTokens,int timeoutSeconds,String safetyIdentifier,String promptVersion) {
  public Request(String model,String effort,ArrayNode input,ArrayNode tools,int maxOutputTokens,int timeoutSeconds,String safetyIdentifier) {
   this(model,effort,input,tools,maxOutputTokens,timeoutSeconds,safetyIdentifier,AssistantState.PROMPT_VERSION);
  }
 }
 record Response(ArrayNode output,String status,long inputTokens,long outputTokens,boolean usageKnown) { }
 class ProviderFailure extends IOException {
  private final String code;private final boolean retryable;private final long retryAfterMillis;
  public ProviderFailure(String code,boolean retryable,long delay){super(code);this.code=code;this.retryable=retryable;this.retryAfterMillis=delay;}
  public String code(){return code;}public boolean retryable(){return retryable;}public long retryAfterMillis(){return retryAfterMillis;}
 }
 Response complete(Request request)throws IOException,InterruptedException;
}

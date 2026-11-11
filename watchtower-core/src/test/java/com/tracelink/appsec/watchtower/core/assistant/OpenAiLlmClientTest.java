package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import com.fasterxml.jackson.databind.JsonNode;

class OpenAiLlmClientTest {
 HttpServer server;AtomicReference<String> body=new AtomicReference<>();AtomicInteger status=new AtomicInteger(200);String reply;
 @BeforeEach void setup()throws Exception {
  reply="{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Recorded evidence\"}]}],\"usage\":{\"input_tokens\":15,\"output_tokens\":5}}";
  server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);server.createContext("/v1/responses",exchange->{body.set(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));exchange.getResponseHeaders().set("Retry-After","2");byte[] bytes=reply.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(status.get(),bytes.length);exchange.getResponseBody().write(bytes);exchange.close();});server.start();
 }
 @AfterEach void stop(){server.stop(0);}
 OpenAiLlmClient client(){return new OpenAiLlmClient(HttpClient.newHttpClient(),URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/v1/"),"synthetic-test-key");}
 LlmClient.Request request(){var input=AssistantState.mapper().createArrayNode();input.addObject().put("role","user").put("content","Explain a rule");return new LlmClient.Request("fixture-model","low",input,AssistantState.mapper().createArrayNode(),256,5,"opaque-user-hash");}
 @Test void sendsStatelessResponsesAndReadsTypedItemsAndUsage()throws Exception{
  var response=client().complete(request());JsonNode payload=AssistantState.mapper().readTree(body.get());assertFalse(payload.get("store").asBoolean());assertEquals("low",payload.path("reasoning").path("effort").asText());assertEquals("reasoning.encrypted_content",payload.path("include").get(0).asText());assertEquals("opaque-user-hash",payload.path("safety_identifier").asText());assertFalse(payload.has("previous_response_id"));assertEquals(15,response.inputTokens());assertEquals("Recorded evidence",AssistantTurnRunner.text(response.output()));
 }
 @Test void structuredRequestsAreStatelessToolFreeStrictJsonAndReadTextUsageAndRefusals()throws Exception{
  reply="{\"status\":\"completed\",\"output\":[{\"type\":\"reasoning\"},{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"name\\\":\\\"x\\\"}\"}]}],\"usage\":{\"input_tokens\":12,\"output_tokens\":3}}";
  var schema=AssistantState.mapper().createObjectNode().put("type","object");
  var request=new OpenAiLlmClient.Structured("fixture-model","low","Name the theme.","{\"rule\":\"r\"}","feedback_theme_name",schema,2048,5,"watchtower-theme");
  var result=client().structured(request);
  assertEquals("{\"name\":\"x\"}",result.text());assertFalse(result.refused());assertEquals(12,result.inputTokens());assertEquals(3,result.outputTokens());assertTrue(result.usageKnown());
  var sent=AssistantState.mapper().readTree(body.get());
  assertFalse(sent.path("store").asBoolean(true));assertFalse(sent.has("tools"));assertEquals("Name the theme.",sent.path("instructions").asText());
  assertEquals("json_schema",sent.path("text").path("format").path("type").asText());assertTrue(sent.path("text").path("format").path("strict").asBoolean());
  assertEquals("low",sent.path("reasoning").path("effort").asText());assertEquals("{\"rule\":\"r\"}",sent.path("input").get(0).path("content").get(0).path("text").asText());
  reply="{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"refusal\",\"refusal\":\"no\"}]}],\"usage\":{}}";
  var refused=client().structured(request);assertTrue(refused.refused());assertFalse(refused.usageKnown());
 }
 @Test void distinguishesRetryableRateLimitsWithoutLeakingProviderBodies(){status.set(429);reply="secret=private-provider-body";var failure=assertThrows(LlmClient.ProviderFailure.class,()->client().complete(request()));assertTrue(failure.retryable());assertEquals(2000,failure.retryAfterMillis());assertFalse(failure.getMessage().contains("private-provider"));}
 @Test void authenticationErrorsArePermanent(){status.set(401);var failure=assertThrows(LlmClient.ProviderFailure.class,()->client().complete(request()));assertFalse(failure.retryable());assertEquals("PROVIDER_AUTHENTICATION",failure.code());}
 @Test void rejectsUnsupportedStatusesMalformedAndOversizedBodies(){reply="not-json";assertThrows(LlmClient.ProviderFailure.class,()->client().complete(request()));reply="{\"status\":\"in_progress\",\"output\":[]}";assertThrows(LlmClient.ProviderFailure.class,()->client().complete(request()));reply="x".repeat(1048577);assertThrows(LlmClient.ProviderFailure.class,()->client().complete(request()));}
 final com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService keys=org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService.class);
 @Test void productionEndpointRejectsUnapprovedPathsAndHosts(){assertThrows(IllegalArgumentException.class,()->new OpenAiLlmClient("http://127.0.0.1/",keys));assertThrows(IllegalArgumentException.class,()->new OpenAiLlmClient("https://api.openai.com/other/",keys));assertThrows(IllegalArgumentException.class,()->new OpenAiLlmClient("https://api.openai.com/v1/?token=private",keys));}
 /** The stored key is read on every call, so a replaced key applies at once on every pod; a refused key is recorded. */
 @Test void readsTheStoredKeyPerCallAndRecordsARejectedKey()throws Exception{
  var key=new AtomicReference<>("");var auth=new AtomicReference<String>();var rejected=new AtomicInteger();
  server.removeContext("/v1/responses");server.createContext("/v1/responses",exchange->{auth.set(exchange.getRequestHeaders().getFirst("Authorization"));exchange.getRequestBody().readAllBytes();byte[] bytes=reply.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(status.get(),bytes.length);exchange.getResponseBody().write(bytes);exchange.close();});
  var client=new OpenAiLlmClient(HttpClient.newHttpClient(),URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/v1/"),key::get,rejected::incrementAndGet);
  assertEquals("PROVIDER_AUTHENTICATION",assertThrows(LlmClient.ProviderFailure.class,()->client.complete(request())).code(),"no key, no request");
  assertNull(auth.get());assertEquals(0,rejected.get(),"a missing key is not a rejected key");
  key.set("sk-first-synthetic-key-0000000000");client.complete(request());assertEquals("Bearer sk-first-synthetic-key-0000000000",auth.get());
  key.set("sk-second-synthetic-key-000000000");status.set(401);
  assertEquals("PROVIDER_AUTHENTICATION",assertThrows(LlmClient.ProviderFailure.class,()->client.complete(request())).code());
  assertEquals("Bearer sk-second-synthetic-key-000000000",auth.get());assertEquals(1,rejected.get());
  status.set(500);assertThrows(LlmClient.ProviderFailure.class,()->client.complete(request()));assertEquals(1,rejected.get(),"only 401/403 mark the key as failing");
 }
 @Test void wholeRequestTimeoutIncludesAStalledResponseBody()throws Exception{
  var release=new java.util.concurrent.CountDownLatch(1);server.removeContext("/v1/responses");server.createContext("/v1/responses",exchange->{exchange.getRequestBody().readAllBytes();exchange.sendResponseHeaders(200,0);exchange.getResponseBody().write('{');exchange.getResponseBody().flush();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{exchange.close();}});
  var r=request();var shortRequest=new LlmClient.Request(r.model(),r.effort(),r.input(),r.tools(),r.maxOutputTokens(),1,r.safetyIdentifier());
  long started=System.nanoTime();try{var failure=assertThrows(LlmClient.ProviderFailure.class,()->client().complete(shortRequest));assertEquals("PROVIDER_TRANSPORT",failure.code());assertTrue(failure.retryable());assertTrue(java.time.Duration.ofNanos(System.nanoTime()-started).toSeconds()<4);}finally{release.countDown();}
 }
}

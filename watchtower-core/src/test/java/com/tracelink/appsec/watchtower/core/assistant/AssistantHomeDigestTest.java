package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.digest.*;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.metrics.*;

/** S7: the weekly digest is written from counts only, and a line with a number that is not a count is dropped. */
class AssistantHomeDigestTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Dashboard View");
 static final long DAY=24*3600*1000L;
 @TempDir Path dir;AssistantFixture fx;StructuredFeatureCall calls;HomeDigestService digests;MetricsCacheService metrics;HomeDashboardService home;
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<OpenAiLlmClient.StructuredReply> replies=new ArrayDeque<>();
 final AtomicLong now=new AtomicLong(Instant.parse("2026-10-21T10:00:00Z").toEpochMilli());

 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",1200,60,true);}
 static final String GOOD="{\"points\":[{\"trend\":\"steady\",\"text\":\"4,532 scans finished and 1 failed or stopped early.\"},{\"trend\":\"up\",\"text\":\"Findings rose to 4,040, up 6% on the week before.\"},{\"trend\":\"attention\",\"text\":\"4 integrations are failing their health check.\"}]}";

 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->AssistantFixture.slice(c,"homeDigest",true,200_000,200_000));
  fx.database.jdbc.update("INSERT INTO application_persistence_locks(lock_name) VALUES (?)","home-digest");
  calls=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{sent.add(request);return replies.poll();});
  metrics=mock(MetricsCacheService.class);home=mock(HomeDashboardService.class);
  when(metrics.getHomeMetrics(anyLong(),anyLong())).thenAnswer(i->(long)i.getArgument(1)>now.get()-DAY?new HomeMetricsSnapshot(4532,4040,29.88*60000):new HomeMetricsSnapshot(4400,3811,28*60000));
  when(home.countIncomplete(anyLong(),anyLong())).thenAnswer(i->(long)i.getArgument(1)>now.get()-DAY?1L:0L);
  var health=mock(ProcessorHealthModel.class);
  var failing=new IntegrationStatus("Acme Bitbucket","Bitbucket","call_merge","bad","Failing","tip",null,null,null);
  when(health.getIntegrations()).thenReturn(List.of(failing,failing,failing,failing));
  when(home.getProcessorHealth()).thenReturn(health);
  Clock clock=new Clock(){@Override public ZoneId getZone(){return ZoneOffset.UTC;}@Override public Clock withZone(ZoneId zone){return this;}@Override public Instant instant(){return Instant.ofEpochMilli(now.get());}@Override public long millis(){return now.get();}};
  digests=new HomeDigestService(calls,fx.database.records,metrics,home,fx.access,fx.settings,fx.database.tx,clock);
 }
 @AfterEach void close(){fx.close();}

 int rows(){return fx.database.records.maps("SELECT d.id AS id FROM AiDigestEntity d",0,100).size();}
 @SuppressWarnings("unchecked") Map<String,Object> digest(Map<String,Object> out){return (Map<String,Object>)out.get("digest");}
 void failedJob(long createdAt){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{var job=new AsyncJobEntity();job.setType(AsyncJobType.CATALOG_SYNC);job.setStatus(AsyncJobStatus.FAILED);job.setDedupKey("k"+createdAt);job.setCreatedAt(createdAt);job.setCreatedBy("system");fx.database.records.insert(job);});
 }

 @Test @SuppressWarnings("unchecked") void aDigestIsWrittenFromCountsOnlyAndKeptWithTheCountsItUsed(){
  failedJob(now.get()-DAY);replies.add(reply(GOOD));
  var out=digests.refresh("alice");var d=digest(out);
  assertEquals("OK",out.get("state"));assertEquals("OK",d.get("status"));assertEquals(3,((List<?>)d.get("points")).size());
  var counts=(Map<String,Object>)d.get("counts");var week=(Map<String,Object>)counts.get("this_week");
  assertEquals(4532,((Number)week.get("scans_finished")).intValue());assertEquals(1,((Number)week.get("failed_background_jobs")).intValue());assertEquals(29.9,((Number)week.get("average_scan_minutes")).doubleValue());
  assertEquals(4,((Number)((Map<String,Object>)counts.get("now")).get("integrations_failing")).intValue());assertEquals(3811,((Number)((Map<String,Object>)counts.get("last_week")).get("findings")).intValue());
  var input=sent.getFirst().input();assertFalse(input.contains("Acme")||input.contains("Bitbucket"),"no integration or repository name is sent");
  assertTrue(input.contains("this_week")&&input.contains("last_week"));assertTrue(sent.getFirst().instructions().contains("Never invent a count"));
  assertEquals(1,rows());assertTrue(fx.budgets.usedToday(AssistantFeature.HOME_DIGEST).get("tokens")>0,"charged to its own share");
  long midnight=Instant.parse("2026-10-21T00:00:00Z").toEpochMilli();
  assertEquals(midnight,((Number)d.get("windowEnd")).longValue(),"whole days: the week ends at the start of today");assertEquals(midnight-7*DAY,((Number)d.get("windowStart")).longValue());
  verify(metrics).getHomeMetrics(midnight-7*DAY,midnight);verify(metrics).getHomeMetrics(midnight-14*DAY,midnight-7*DAY);
 }
 @Test void theCurrentCountsAreKeptForAMinuteSoACardDoesNotRecountOnEveryTurn(){
  var first=digests.currentCounts();
  now.addAndGet(30_000);
  digests.currentCounts();
  verify(home,times(1)).getProcessorHealth();
  assertSame(first,digests.currentCounts());
  now.addAndGet(31_000);
  digests.currentCounts();
  verify(home,times(2)).getProcessorHealth();
 }
 @Test void aLineWithANumberThatIsNotACountIsDroppedAndAnUnusableAnswerKeepsTheCounts(){
  replies.add(reply("{\"points\":[{\"trend\":\"up\",\"text\":\"Findings rose to 9,999.\"},{\"trend\":\"steady\",\"text\":\"4,532 scans finished.\"},{\"trend\":\"down\",\"text\":\"Scans fell 55% on last week.\"}]}"));
  var kept=(List<?>)digest(digests.refresh("alice")).get("points");
  assertEquals(1,kept.size(),"the invented count and the invented percentage are dropped");
  now.addAndGet(6*60*1000);replies.add(reply("{\"points\":[{\"trend\":\"up\",\"text\":\"Findings rose to 9,999.\"}]}"));
  var none=digest(digests.refresh("alice"));assertEquals("COUNTS_ONLY",none.get("status"));assertTrue(((List<?>)none.get("points")).isEmpty());assertNotNull(none.get("counts"),"the counts stay");
  now.addAndGet(6*60*1000);replies.add(reply("not json"));assertEquals("COUNTS_ONLY",digest(digests.refresh("alice")).get("status"));
 }
 @Test void aLineThatIsLongOddOrLooksLikeASecretIsDropped(){
  var allowed=Set.of("4532","1");
  assertNull(HomeDigestService.accept("not json",allowed));
  var kept=HomeDigestService.accept("{\"points\":[{\"trend\":\"bogus\",\"text\":\"4,532 scans.\"},{\"trend\":\"steady\",\"text\":\""+"x".repeat(120)+"\"},{\"trend\":\"steady\",\"text\":\"1 scan failed with password=hunter2hunter2\"},{\"trend\":\"steady\",\"text\":\"4,532 scans finished.\"},{\"trend\":\"steady\",\"text\":\"\"}]}",allowed);
  assertEquals(List.of("4,532 scans finished."),kept.stream().map(p->p.get("text")).toList());
  assertEquals(3,HomeDigestService.accept("{\"points\":[{\"trend\":\"up\",\"text\":\"a\"},{\"trend\":\"up\",\"text\":\"b\"},{\"trend\":\"up\",\"text\":\"c\"},{\"trend\":\"up\",\"text\":\"d\"}]}",allowed).size(),"at most three lines");
  assertTrue(HomeDigestService.numbersKnown("Up 6% to 4,040.",Set.of("6%","4040")));assertFalse(HomeDigestService.numbersKnown("Up 7%.",Set.of("6%")));assertTrue(HomeDigestService.numbersKnown("No numbers here.",Set.of()));
 }
 @Test void aPersonCanWriteAnotherDigestOnlyEveryFiveMinutesAndNeedsBothGrants(){
  replies.add(reply(GOOD));digests.refresh("alice");
  assertEquals(429,assertThrows(ResponseStatusException.class,()->digests.refresh("bob")).getStatusCode().value());assertEquals(1,sent.size());
  now.addAndGet(5*60*1000+1);replies.add(reply(GOOD));digests.refresh("bob");assertEquals(2,rows());
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","Scan Dashboard View");
  assertThrows(AccessDeniedException.class,()->digests.refresh("mallory"));assertEquals(2,sent.size());
 }
 @Test void theMondayJobWritesOneDigestPerWeekAndSkipsWhenItCannotWork()throws Exception{
  replies.add(reply(GOOD));digests.scheduled();
  assertEquals(1,rows());assertEquals("system",fx.database.records.maps("SELECT d.createdBy AS who FROM AiDigestEntity d",0,5).getFirst().get("who"));
  digests.scheduled();digests.scheduled();assertEquals(1,rows(),"the same week is not written twice");assertEquals(1,sent.size());
  now.addAndGet(7*DAY);replies.add(reply("not json"));digests.scheduled();
  assertEquals(2,rows(),"the next week gets its own, even when the assistant gave nothing usable");
  digests.scheduled();assertEquals(2,rows(),"and it is not retried every hour");
  now.addAndGet(7*DAY);fx.configure(c->AssistantFixture.slice(c,"homeDigest",false,200_000,200_000));digests.scheduled();assertEquals(2,rows(),"nothing when the feature is off");
  fx.configure(c->AssistantFixture.slice(c,"homeDigest",true,500,500));digests.scheduled();assertEquals(2,rows(),"a used-up share writes nothing and tries again later");
 }
 @Test void theLatestDigestIsForAnyoneWhoCanSeeTheDashboardAndWritingNeedsTheGrantsAndTheFeature()throws Exception{
  var before=digests.latest(GRANTS);assertEquals(Boolean.TRUE,before.get("enabled"));assertEquals(Boolean.TRUE,before.get("canWrite"));assertNull(before.get("digest"));
  replies.add(reply(GOOD));digests.refresh("alice");
  var viewer=digests.latest(Set.of("Scan Dashboard View"));assertEquals(Boolean.FALSE,viewer.get("canWrite"),"reading needs only the dashboard grant");assertNotNull(viewer.get("digest"));
  fx.configure(c->AssistantFixture.slice(c,"homeDigest",false,200_000,200_000));
  var off=digests.latest(GRANTS);assertEquals(Boolean.FALSE,off.get("enabled"));assertEquals(Boolean.FALSE,off.get("canWrite"));assertNull(off.get("digest"),"switched off, the stored digest is not served either");
  assertEquals("OFF",digests.refresh("alice").get("state"));assertEquals(1,sent.size());
 }

 @Test void aLineThatReadsAsADifferentNumberThanWasCheckedIsDropped(){
  var allowed=new HashSet<>(Set.of("1","2","4","12","20","4532","4040"));
  for(String bad:List.of("1\u200B4 scans failed","1,2 scans failed","2,0 integrations failing","1,23 scans failed","1k scans failed","2x as many scans","the 3rd scan failed","\uFF14\uFF10 scans failed","\u0664\u0660 scans failed",
    "four integrations are failing","twice as many scans failed","scans doubled","a dozen jobs failed","half of the scans failed","a thousand findings","Up 12 percent","4 scans <b>failed</b>","see http://x.example for 4 scans","Approve the 4 requests","Decline 2 requests","em dash \u2014 4 scans")){
   var kept=HomeDigestService.accept("{\"points\":[{\"trend\":\"attention\",\"text\":\""+bad+"\"}]}",allowed);
   assertTrue(kept==null||kept.isEmpty(),bad);
  }
  for(String ok:List.of("4,532 scans finished and 1 failed.","Findings rose to 4,040.","2 integrations failing.","12 jobs failed, up 12% on the week before","No change this week."))
   assertEquals(1,HomeDigestService.accept("{\"points\":[{\"trend\":\"steady\",\"text\":\""+ok+"\"}]}",new HashSet<>(Set.of("1","2","12","12%","4532","4040"))).size(),ok);
 }
 @Test void twoQuickRequestsRunOnceAndAFailedRequestIsLimitedToo(){
  replies.add(reply(GOOD));
  var nested=new ArrayList<Throwable>();
  // While the first request waits for the model, a second arrives.
  var provider=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{sent.add(request);try{digests.refresh("bob");}catch(Throwable t){nested.add(t);}return replies.poll();});
  digests=new HomeDigestService(provider,fx.database.records,metrics,home,fx.access,fx.settings,fx.database.tx,Clock.fixed(Instant.ofEpochMilli(now.get()),ZoneOffset.UTC));
  digests.refresh("alice");
  assertEquals(1,nested.size());assertEquals(429,((ResponseStatusException)nested.getFirst()).getStatusCode().value(),"the second request sees the first one's slot");assertEquals(1,sent.size());
  var failing=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{throw new LlmClient.ProviderFailure("PROVIDER_PROTOCOL",false,0);});
  digests=new HomeDigestService(failing,fx.database.records,metrics,home,fx.access,fx.settings,fx.database.tx,Clock.fixed(Instant.ofEpochMilli(now.get()+10*60*1000),ZoneOffset.UTC));
  assertEquals(503,assertThrows(ResponseStatusException.class,()->digests.refresh("alice")).getStatusCode().value());
  assertEquals(429,assertThrows(ResponseStatusException.class,()->digests.refresh("alice")).getStatusCode().value(),"a request that failed still used its slot");
  assertEquals("OK",((Map<?,?>)digests.latest(GRANTS).get("digest")).get("status"));
 }
 @Test void aFailedWeeklyAttemptWaitsHoursAndAUsedUpShareCostsNoCounting()throws Exception{
  var failing=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{sent.add(request);throw new LlmClient.ProviderFailure("PROVIDER_PROTOCOL",false,0);});
  digests=new HomeDigestService(failing,fx.database.records,metrics,home,fx.access,fx.settings,fx.database.tx,new Clock(){@Override public ZoneId getZone(){return ZoneOffset.UTC;}@Override public Clock withZone(ZoneId zone){return this;}@Override public Instant instant(){return Instant.ofEpochMilli(now.get());}@Override public long millis(){return now.get();}});
  digests.scheduled();assertEquals(1,sent.size());
  now.addAndGet(3600*1000);digests.scheduled();assertEquals(1,sent.size(),"an hour later it does not ask again");
  now.addAndGet(6*3600*1000);digests.scheduled();assertEquals(2,sent.size(),"after the wait it tries again");
  assertNull(digests.latest(GRANTS).get("digest"),"a failed attempt is never shown");
  reset(metrics,home);fx.configure(c->AssistantFixture.slice(c,"homeDigest",true,500,500));
  now.addAndGet(7*3600*1000);digests.scheduled();
  verifyNoInteractions(metrics,home);assertEquals(2,sent.size());
 }
}

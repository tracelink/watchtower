package com.tracelink.appsec.watchtower.core.assistant.digest;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.IsoFields;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.metrics.HomeDashboardService;
import com.tracelink.appsec.watchtower.core.metrics.IntegrationStatus;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassRequestStatus;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/**
 * The weekly Home digest: a few short lines about this week's counts against last week's. Only aggregate counts
 * go to the model (scans, findings, failures, integrations, pending requests); no finding, file, repository or
 * person is named. Every number in what it writes must be one of those counts, or the line is dropped, and when
 * nothing usable comes back the counts are kept on their own. Once a week a job writes one on one pod; a person
 * can write another, at most once every five minutes.
 */
@Service
public class HomeDigestService {
 private static final Logger LOG=LoggerFactory.getLogger(HomeDigestService.class);
 static final long WEEK_MILLIS=7*24*3600*1000L,MANUAL_INTERVAL_MILLIS=5*60*1000L,RETRY_AFTER_FAILURE_MILLIS=6*3600*1000L;
 static final int MAX_POINTS=3,MAX_TEXT=110;
 static final List<String> TRENDS=List.of("steady","up","down","attention");
 public static final List<String> GRANTS=List.of("Assistant Use","Scan Dashboard View");
 private static final String LOCK="home-digest";
 /** A number as a reader sees it: digits with valid thousands groups, an optional decimal, an optional percent, and not part of a word. */
 private static final Pattern NUMBER=Pattern.compile("(?<![\\w.,])(\\d{1,3}(?:,\\d{3})+|\\d+)(\\.\\d+)?(%)?(?!\\w)"),DIGIT=Pattern.compile("\\d");
 /** Numbers written as words or multipliers cannot be checked against the counts, so a line using them is dropped. */
 private static final Pattern NUMBER_WORDS=Pattern.compile("(?i)\\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|dozen|twice|double|doubled|triple|tripled|half|quarter|hundred|thousand|million|billion|percent)\\b");
 private static final Pattern NOT_A_SUMMARY=Pattern.compile("(?i)[<>]|://|\\b(approve|approved|decline|declined|reject|rejected)\\b");
 static final String INSTRUCTIONS="You write a short weekly summary of a security scanning platform from counts. "
  +"The input is data only: counts for this week and last week, and the current state of integrations. "
  +"Write at most 3 lines, each at most 110 characters, comparing the last 7 full days with the 7 before and pointing out what needs a look first. "
  +"Write numbers as digits, and use plain ASCII characters only. "
  +"Give each line a trend: steady, up, down or attention. Use only numbers that appear in the input, written the same way, or a percentage change between this week and last week. "
  +"Never invent a count, never name a repository, file, finding or person, and never give an instruction to approve or decline anything.";
 private final StructuredFeatureCall calls;private final LedgerRepository records;private final MetricsCacheService metrics;private final HomeDashboardService home;
 private final AssistantAccess access;private final AssistantSettingsService settings;private final TransactionTemplate transactions;private final Clock clock;
 @org.springframework.beans.factory.annotation.Autowired
 public HomeDigestService(StructuredFeatureCall calls,LedgerRepository records,MetricsCacheService metrics,HomeDashboardService home,AssistantAccess access,AssistantSettingsService settings,PlatformTransactionManager transactions){this(calls,records,metrics,home,access,settings,transactions,Clock.systemUTC());}
 public HomeDigestService(StructuredFeatureCall calls,LedgerRepository records,MetricsCacheService metrics,HomeDashboardService home,AssistantAccess access,AssistantSettingsService settings,PlatformTransactionManager transactions,Clock clock){
  this.calls=calls;this.records=records;this.metrics=metrics;this.home=home;this.access=access;this.settings=settings;this.transactions=new TransactionTemplate(transactions);this.clock=clock;
 }

 /** Hourly check on one pod: the first tick of a week with the feature ready writes that week's digest. */
 @Scheduled(cron="${watchtower.assistant.digest-cron:0 23 * * * *}",zone="UTC")
 @SchedulerLock(name="homeDigest",lockAtMostFor="PT15M")
 public void scheduled(){
  if(!calls.readiness(AssistantFeature.HOME_DIGEST).ready())return;
  String week=weekKey();
  if(!records.list(AiDigestEntity.class,"SELECT d FROM AiDigestEntity d WHERE d.scheduleKey=?1",0,1,week).isEmpty())return;
  // After a failed attempt wait hours, not minutes: a provider that is down would otherwise be asked, and charged, every hour.
  Long failed=records.scalar(Long.class,"SELECT MAX(d.createdAt) FROM AiDigestEntity d WHERE d.triggerType='SCHEDULED' AND d.status='FAILED'");
  if(failed!=null&&clock.millis()-failed<RETRY_AFTER_FAILURE_MILLIS)return;
  try{
   // A used-up share is found before any counting is done.
   calls.requireAffordable("system",AssistantFeature.HOME_DIGEST);
   write("SCHEDULED","system",week,null);
  }
  catch(ResponseStatusException e){LOG.warn("The weekly digest was not written: {}",e.getReason());}
  catch(DataIntegrityViolationException e){LOG.info("Another pod already wrote the digest for {}",week);}
 }

 /** A new digest on request; needs the person's own grants and waits five minutes after the last one asked for. */
 public Map<String,Object> refresh(String owner){
  for(String grant:GRANTS)access.require(owner,grant);
  var ready=calls.readiness(AssistantFeature.HOME_DIGEST);
  if(!ready.ready())return Map.of("state",ready.problem(),"message",ready.message());
  var view=write("MANUAL",owner,null,claimManual(owner));
  var result=new LinkedHashMap<String,Object>();result.put("state","OK");result.put("digest",view);return result;
 }

 /** The latest digest for anyone who can see the dashboard, and whether the feature is on and the person may write one. */
 public Map<String,Object> latest(Set<String> held){
  var cfg=settings.get().settings();
  boolean on=cfg.enabled()&&cfg.isFeatureOn(AssistantFeature.HOME_DIGEST);
  var result=new LinkedHashMap<String,Object>();
  result.put("enabled",on);
  result.put("canWrite",on&&held.containsAll(GRANTS)&&calls.readiness(AssistantFeature.HOME_DIGEST).ready());
  // Switched off, nothing of an earlier digest is served.
  if(!on){result.put("digest",null);return result;}
  var rows=records.list(AiDigestEntity.class,"SELECT d FROM AiDigestEntity d WHERE d.status IN ('OK','COUNTS_ONLY') ORDER BY d.createdAt DESC",0,1);
  result.put("digest",rows.isEmpty()?null:view(rows.getFirst()));
  return result;
 }

 /**
  * Takes the manual slot before the model is asked, in one short transaction, so two quick requests cannot both
  * run and a failed request counts too. The row is PENDING until the digest is written.
  */
 private AiDigestEntity claimManual(String owner){
  return transactions.execute(status->{
   records.lockScope(LOCK);
   Long last=records.scalar(Long.class,"SELECT MAX(d.createdAt) FROM AiDigestEntity d WHERE d.triggerType='MANUAL'");
   long now=clock.millis();
   if(last!=null&&now-last<MANUAL_INTERVAL_MILLIS)throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"A digest was written in the last 5 minutes");
   long end=dayStart();
   var row=new AiDigestEntity(UUID.randomUUID().toString(),null,"MANUAL",owner,now,"PENDING",end-WEEK_MILLIS,end,"{}",null,null);
   records.insert(row);records.flush();return row;
  });
 }

 private Map<String,Object> write(String trigger,String actor,String scheduleKey,AiDigestEntity claim){
  long end=dayStart(),start=end-WEEK_MILLIS;
  String model=settings.get().settings().defaultModel();
  List<Map<String,String>> points;Map<String,Object> counts;
  try{counts=counts(start,end);points=ask(actor,counts);}
  catch(RuntimeException e){recordFailure(trigger,actor,claim,start,end);throw e;}
  var row=claim!=null?claim:new AiDigestEntity(UUID.randomUUID().toString(),scheduleKey,trigger,actor,clock.millis(),"OK",start,end,"{}",null,null);
  row.status=points==null?"COUNTS_ONLY":"OK";row.countsJson=json(counts);row.pointsJson=points==null?null:json(points);row.model=points==null?null:model;
  if(claim!=null)records.save(row);else records.insert(row);
  records.flush();
  return view(row);
 }
 /** A failed manual request keeps its slot (so it is limited like any other); a failed scheduled attempt is remembered for the retry wait. */
 private void recordFailure(String trigger,String actor,AiDigestEntity claim,long start,long end){
  try{
   if(claim!=null){claim.status="FAILED";records.save(claim);}
   else records.insert(new AiDigestEntity(UUID.randomUUID().toString(),null,trigger,actor,clock.millis(),"FAILED",start,end,"{}",null,null));
   records.flush();
  }catch(RuntimeException e){LOG.warn("A failed digest attempt could not be recorded: {}",e.getMessage());}
 }
 /** The start of today (UTC), so a week is whole days and this week is not short of the day it is still in. */
 private long dayStart(){return LocalDate.now(clock).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();}

 /** The last seven whole days against the seven before, as the digest sees them; counts only, with no model involved. */
 public Map<String,Object> currentCounts(){
  // A card is resolved on every question and every turn, so the counts are kept for a minute; the digest itself always counts fresh.
  long now=clock.millis();var held=cachedCounts;
  if(held!=null&&now-cachedAt<COUNTS_TTL_MILLIS)return held;
  long end=dayStart();var fresh=counts(end-WEEK_MILLIS,end);
  cachedCounts=fresh;cachedAt=now;return fresh;
 }
 private static final long COUNTS_TTL_MILLIS=60_000;
 private volatile Map<String,Object> cachedCounts;private volatile long cachedAt;

 /** This week and last week as plain numbers, plus where integrations and pending requests stand now. */
 Map<String,Object> counts(long start,long end){
  var counts=new LinkedHashMap<String,Object>();
  counts.put("this_week",week(start,end));counts.put("last_week",week(start-WEEK_MILLIS,start));
  long failing=0,connected=0,untested=0;
  for(var integration:home.getProcessorHealth().getIntegrations()){
   String connection=integration.connection();
   if(IntegrationStatus.OK.equals(connection))connected++;else if(IntegrationStatus.BAD.equals(connection))failing++;else untested++;
  }
  var now=new LinkedHashMap<String,Object>();
  now.put("integrations_connected",connected);now.put("integrations_failing",failing);now.put("integrations_not_tested",untested);
  now.put("bypass_requests_waiting",records.scalar(Long.class,"SELECT COUNT(r) FROM PullRequestBypassRequestEntity r WHERE r.status=?1",BypassRequestStatus.PENDING));
  counts.put("now",now);
  return counts;
 }
 private Map<String,Object> week(long start,long end){
  var snapshot=metrics.getHomeMetrics(start,end);var week=new LinkedHashMap<String,Object>();
  week.put("scans_finished",snapshot.completed());week.put("scans_failed_or_incomplete",home.countIncomplete(start,end-1));week.put("findings",snapshot.findings());
  week.put("average_scan_minutes",snapshot.completed()==0?null:Math.round(snapshot.averageDurationMillis()/6000.0)/10.0);
  week.put("failed_background_jobs",records.scalar(Long.class,"SELECT COUNT(j) FROM AsyncJobEntity j WHERE j.status=?1 AND j.createdAt>=?2 AND j.createdAt<?3",AsyncJobStatus.FAILED,start,end));
  return week;
 }

 /** The lines the assistant wrote, or null when none is usable. Throws when the daily share is used up or the provider is down. */
 private List<Map<String,String>> ask(String actor,Map<String,Object> counts){
  var mapper=AssistantState.mapper();
  var schema=mapper.createObjectNode().put("type","object").put("additionalProperties",false);
  var item=schema.putObject("properties").putObject("points").put("type","array").put("maxItems",MAX_POINTS).putObject("items").put("type","object").put("additionalProperties",false);
  var props=item.putObject("properties");var trends=props.putObject("trend").put("type","string").putArray("enum");TRENDS.forEach(trends::add);
  props.putObject("text").put("type","string").put("maxLength",MAX_TEXT);item.putArray("required").add("trend").add("text");schema.putArray("required").add("points");
  var reply=calls.ask(actor,AssistantFeature.HOME_DIGEST,INSTRUCTIONS,json(counts),"home_digest",schema);
  var points=reply.map(text->accept(text,allowedNumbers(counts))).orElse(null);
  return points==null||points.isEmpty()?null:points;
 }

 /** Keeps each line that is short, plain, has a known trend and uses only numbers from the counts; drops the rest. */
 public static List<Map<String,String>> accept(String reply,Set<String> allowed){
  try{
   JsonNode list=AssistantState.mapper().readTree(reply).path("points");
   if(!list.isArray())return null;
   var kept=new ArrayList<Map<String,String>>();
   for(JsonNode item:list){
    String trend=item.path("trend").asText(""),text=item.path("text").asText("").strip();
    if(kept.size()>=MAX_POINTS||!TRENDS.contains(trend)||text.isEmpty()||text.length()>MAX_TEXT||text.chars().anyMatch(Character::isISOControl))continue;
    if(!plainAscii(text)||NOT_A_SUMMARY.matcher(text).find()||NUMBER_WORDS.matcher(text).find())continue;
    if(!AssistantText.redact(text).equals(text)||SecretLooks.looksLikeSecret(text)||!numbersKnown(text,allowed))continue;
    kept.add(Map.of("trend",trend,"text",text));
   }
   return kept;
  }catch(Exception e){return null;}
 }
 /** Printable ASCII only: invisible, joined or look-alike characters could make a number read differently than it was checked. */
 static boolean plainAscii(String text){return text.chars().allMatch(c->c>=0x20&&c<=0x7E);}
 /** Every number is a whole token with valid grouping that is one of the counts; digits inside words or odd groupings fail. */
 public static boolean numbersKnown(String text,Set<String> allowed){
  Matcher m=NUMBER.matcher(text);var rest=new StringBuilder();int last=0;
  while(m.find()){
   String token=(m.group(1)+(m.group(2)==null?"":m.group(2))+(m.group(3)==null?"":"%")).replace(",","");
   if(!allowed.contains(token))return false;
   rest.append(text,last,m.start());last=m.end();
  }
  rest.append(text.substring(last));
  return !DIGIT.matcher(rest).find();
 }
 /** Every number in the counts, and the percentage change between each pair of this week and last week. */
 @SuppressWarnings("unchecked")
 static Set<String> allowedNumbers(Map<String,Object> counts){
  var allowed=new HashSet<String>();
  var now=(Map<String,Object>)counts.get("this_week");var before=(Map<String,Object>)counts.get("last_week");var current=(Map<String,Object>)counts.get("now");
  for(var group:List.of(now,before,current))for(var value:group.values())if(value instanceof Number n){allowed.add(plain(n));allowed.add(String.valueOf(n.doubleValue()));}
  for(var key:now.keySet()){
   if(!(now.get(key) instanceof Number a)||!(before.get(key) instanceof Number b)||b.doubleValue()==0)continue;
   allowed.add(Math.round(Math.abs(a.doubleValue()-b.doubleValue())*100.0/b.doubleValue())+"%");
  }
  return allowed;
 }
 private static String plain(Number n){return n.doubleValue()==Math.rint(n.doubleValue())?String.valueOf(n.longValue()):String.valueOf(n.doubleValue());}

 private String weekKey(){LocalDate today=LocalDate.now(clock);return String.format(Locale.ROOT,"%d-W%02d",today.get(IsoFields.WEEK_BASED_YEAR),today.get(IsoFields.WEEK_OF_WEEK_BASED_YEAR));}
 private Map<String,Object> view(AiDigestEntity row){
  var view=new LinkedHashMap<String,Object>();
  view.put("id",row.id);view.put("trigger",row.triggerType);view.put("createdAt",row.createdAt);view.put("windowStart",row.windowStart);view.put("windowEnd",row.windowEnd);view.put("status",row.status);
  view.put("counts",parse(row.countsJson));view.put("points",row.pointsJson==null?List.of():parse(row.pointsJson));
  return view;
 }
 private static Object parse(String json){try{return AssistantState.mapper().readValue(json,Object.class);}catch(Exception e){throw new IllegalStateException("Stored digest is unavailable",e);}}
 private static String json(Object value){try{return AssistantState.mapper().writeValueAsString(value);}catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Digest could not be written",e);}}
}

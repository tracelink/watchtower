package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.alerting.AlertAggregation;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.assistant.context.*;
import com.tracelink.appsec.watchtower.core.assistant.digest.HomeDigestService;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.metrics.HomeDashboardService;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.metrics.ModuleStatus;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** The cards for Home, the repository list, alert settings, jobs, a scan type's metrics and the scanner modules: counts and names only. */
class AssistantPageContextTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Dashboard View","Repository Settings View","Alert Settings View","Scan Results View","Module Settings Modify");
 @TempDir Path dir;AssistantFixture fx;ContextService contexts;HomeDigestService digests;MetricsCacheService metrics;HomeDashboardService dashboard;ModuleControlService controls;

 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",true));
  for(var name:fx.database.jdbc.queryForList("SELECT constraint_name FROM information_schema.table_constraints WHERE table_name='alert_routes' AND constraint_type='CHECK'",String.class))fx.database.jdbc.execute("ALTER TABLE alert_routes DROP CONSTRAINT \""+name+"\"");
  for(var name:fx.database.jdbc.queryForList("SELECT constraint_name FROM information_schema.table_constraints WHERE table_name='repositories' AND constraint_type IN ('UNIQUE','FOREIGN KEY')",String.class))fx.database.jdbc.execute("ALTER TABLE repositories DROP CONSTRAINT \""+name+"\"");
  for(var name:fx.database.jdbc.queryForList("SELECT index_name FROM information_schema.indexes WHERE table_name='repositories' AND index_type_name='UNIQUE INDEX'",String.class))fx.database.jdbc.execute("DROP INDEX \""+name+"\"");
  digests=mock(HomeDigestService.class);metrics=mock(MetricsCacheService.class);dashboard=mock(HomeDashboardService.class);controls=mock(ModuleControlService.class);
  when(digests.currentCounts()).thenReturn(Map.of("this_week",Map.of("scans_finished",4532,"findings",4040),"last_week",Map.of("scans_finished",4400),"now",Map.of("integrations_failing",4)));
  var records=fx.database.records;
  contexts=new ContextService(fx.access,fx.settings,List.of(new PageContextProviders.Home(digests),new PageContextProviders.Repositories(records),new PageContextProviders.AlertSettings(records),
    new PageContextProviders.Jobs(records),new PageContextProviders.Metrics(metrics),new PageContextProviders.ScannerModules(dashboard,controls)));
 }
 @AfterEach void close(){fx.close();}

 static ContextRequest page(String kind,String scanType){return new ContextRequest(1,kind,new ContextRequest.Ids(scanType,null,null,null,null));}
 ContextCard card(String kind,String scanType){return contexts.forSubmit("alice",page(kind,scanType));}
 void repository(String name,Long ruleset,boolean paused){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{var r=new RepositoryEntity();r.setApiLabel("Bitbucket");r.setRepoName(name);r.setScanType(CodeScanType.PULL_REQUEST);r.setScanningPaused(paused);
   if(ruleset!=null)r.setRuleset(fx.database.records.find(RulesetEntity.class,ruleset));fx.database.records.insert(r);});
 }
 long ruleset(String name){return new TransactionTemplate(fx.database.tx).execute(s->{var r=new RulesetEntity();r.setName(name);r.setDescription("d");r.setDesignation(RulesetDesignation.PRIMARY);fx.database.records.insert(r);return r.getId();});}
 void job(AsyncJobType type,AsyncJobStatus status,String error,long ageMillis){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{var job=new AsyncJobEntity();job.setType(type);job.setStatus(status);job.setDedupKey("k"+System.nanoTime());job.setCreatedAt(System.currentTimeMillis()-ageMillis);job.setCreatedBy("system");job.setError(error);fx.database.records.insert(job);});
 }

 @Test void homeIsTheDigestsCountsAndNothingElse(){
  var card=card("home",null);
  assertTrue(card.isOk());assertEquals("Page · Home",card.title());assertEquals(4,((Map<?,?>)card.facts().get("now")).get("integrations_failing"));
  var preview=contexts.preview("alice",page("home",null));
  assertEquals("Home",preview.label());assertTrue(preview.lines().contains("Last 7 days: 4,532 scans · 4,040 findings"),"numbers read as they do on the page");assertTrue(preview.lines().contains("4 integrations failing"));
 }
 @Test void aCountOfOneReadsInTheSingular(){
  when(digests.currentCounts()).thenReturn(Map.of("this_week",Map.of("scans_finished",1,"findings",1),"last_week",Map.of("scans_finished",1),"now",Map.of("integrations_failing",1)));
  var preview=contexts.preview("alice",page("home",null));
  assertTrue(preview.lines().contains("Last 7 days: 1 scan · 1 finding"),preview.lines().toString());assertTrue(preview.lines().contains("1 integration failing"),preview.lines().toString());
 }
 @Test void theRepositoryListCountsRepositoriesAndRulesetsWithoutNamingAny(){
  long set=ruleset("Default");repository("payments-api",set,false);repository("ledger",set,true);repository("website",null,false);
  var card=card("repositories",null);
  assertEquals(3L,card.facts().get("repositories"));assertEquals(2L,card.facts().get("with_ruleset"));assertEquals(1L,card.facts().get("without_ruleset"));assertEquals(1L,card.facts().get("scanning_paused"));
  assertFalse(card.toString().contains("payments-api"),"no repository name");
  assertEquals("3 repositories · 1 without a ruleset",contexts.preview("alice",page("repositories",null)).lines().getFirst());
 }
 @Test @SuppressWarnings("unchecked") void alertSettingsShowChannelNamesAndRouteCountsButNeverAWebhookAddress(){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var platform=new AlertChannelEntity();platform.setName("platform");platform.setWebhookUrl("https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=faketoken");fx.database.records.insert(platform);
   var odd=new AlertChannelEntity();odd.setName("sk-abcdefghijklmnopqrstuvwxyz");odd.setWebhookUrl("https://chat.googleapis.com/v1/spaces/BBBB/messages?key=k&token=other");fx.database.records.insert(odd);
   var r=new AlertRouteEntity();r.setAlertType("SECRET_DETECTED");r.setChannel(platform);r.setMinPriority(RulePriority.MEDIUM);r.setAggregation(AlertAggregation.PER_SCAN);r.setDedupeWindowHours(720);r.setUpdatedAt(1);fx.database.records.insert(r);
  });
  var card=card("alert_settings",null);var text=card.toString();
  assertEquals(2L,card.facts().get("channels"));assertEquals(1L,card.facts().get("routes"));assertEquals(Map.of("SECRET_DETECTED",1L),card.facts().get("routes_by_type"));
  assertFalse(text.contains("faketoken")||text.contains("googleapis")||text.contains("sk-abcdef"),"no address, and a secret-looking name is withheld");
  assertTrue(((List<Map<String,Object>>)card.facts().get("channel_names")).stream().anyMatch(c->"(withheld)".equals(c.get("name"))));
  assertEquals("2 channels · 1 route",contexts.preview("alice",page("alert_settings",null)).lines().getFirst());
 }
 @Test @SuppressWarnings("unchecked") void jobsCountWhatWaitsAndFailedAndCleanTheErrorsOfTheLastFew(){
  job(AsyncJobType.INTEGRATION_HEALTH,AsyncJobStatus.FAILED,"Authorization failed with token=abc123def456abc123def456abc123def456 for registry",60_000);
  job(AsyncJobType.CATALOG_SYNC,AsyncJobStatus.FAILED,"Rate limited",120_000);
  job(AsyncJobType.EXPORT_RUN,AsyncJobStatus.QUEUED,null,1000);
  job(AsyncJobType.CATALOG_SYNC,AsyncJobStatus.DONE,null,3000);
  job(AsyncJobType.RULE_CANDIDATE_TEST,AsyncJobStatus.FAILED,"boom from a job the Queue page does not show",1000);
  var card=card("jobs",null);
  assertEquals(2L,card.facts().get("failed_24h"));assertEquals(1L,card.facts().get("queued"));assertEquals(1L,card.facts().get("done_24h"));assertEquals(0L,card.facts().get("running"));
  var recent=(List<Map<String,Object>>)card.facts().get("recent_failures");
  assertEquals(2,recent.size());assertEquals("within the hour",recent.getFirst().get("when"));assertTrue(recent.getFirst().get("error").toString().contains("withheld"));assertFalse(card.toString().contains("abc123")||card.toString().contains("boom"));
  assertEquals("2 failed in 24 h · 1 waiting",contexts.preview("alice",page("jobs",null)).lines().getFirst());
 }
 @Test void aScanTypesMetricsNeedAKnownTypeAndRebuildFromTheirIds(){
  when(metrics.getScanCount(CodeScanType.PULL_REQUEST)).thenReturn(2533L);when(metrics.getScanCountToday(CodeScanType.PULL_REQUEST)).thenReturn(12L);when(metrics.getViolationCount(CodeScanType.PULL_REQUEST)).thenReturn(1567L);
  var card=card("metrics","pull_request");
  assertTrue(card.isOk());assertEquals("Page · Metrics (Pull Request)",card.title());assertEquals(2533L,card.facts().get("scans"));assertEquals("pull_request",card.ids().get("scanType"));
  assertEquals("Metrics (Pull Request)",contexts.preview("alice",page("metrics","pull_request")).label());
  assertEquals("Pull Request · 2,533 scans · 1,567 findings",contexts.preview("alice",page("metrics","pull_request")).lines().getFirst());
  assertEquals(ContextCard.UNAVAILABLE,card("metrics","made_up").state());assertEquals(ContextCard.UNAVAILABLE,card("metrics",null).state());
  assertTrue(contexts.revalidate("alice",card).isOk(),"a stored card is rebuilt from its ids on every turn");
 }
 @Test @SuppressWarnings("unchecked") void theScannerModulesShowStateAndWhichFilesEachRunsOn(){
  when(dashboard.getModuleStatuses()).thenReturn(List.of(new ModuleStatus("PMD","code","Java rules","ready","ok"),new ModuleStatus("Regex","code","Patterns","setup","needs setup"),new ModuleStatus("Checkov","code","IaC","off","off")));
  when(controls.policy("PMD")).thenReturn(new ModuleControlService.Policy("pmd",true,1,null));
  when(controls.policy("Regex")).thenReturn(new ModuleControlService.Policy("regex",true,1,List.of()));
  when(controls.policy("Checkov")).thenReturn(new ModuleControlService.Policy("checkov",false,1,List.of("tf","yaml")));
  var card=card("scanner_modules",null);
  assertEquals(1L,card.facts().get("ready"));assertEquals(1L,card.facts().get("needs_setup"));assertEquals(1L,card.facts().get("off"));
  var modules=(List<Map<String,Object>>)card.facts().get("modules");
  assertEquals("its default files",modules.get(0).get("runs_on"));assertEquals("every file",modules.get(1).get("runs_on"));assertEquals(List.of("tf","yaml"),modules.get(2).get("runs_on"));
  assertEquals("1 ready · 1 need setup · 1 off",contexts.preview("alice",page("scanner_modules",null)).lines().getFirst());
 }
 @Test void aPageIsUnavailableWithoutItsGrantAndAStoredCardStopsTheTurnWhenAccessIsRevoked(){
  when(fx.access.authorities("viewer")).thenReturn(Set.of("Assistant Use"));
  for(String kind:List.of("home","repositories","alert_settings","jobs","scanner_modules"))assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("viewer",page(kind,null)).state(),kind);
  var stored=card("home",null);
  assertThrows(AccessDeniedException.class,()->contexts.revalidate("viewer",stored));
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",new ContextRequest(1,"made_up_page",new ContextRequest.Ids(null,null,null,null,null))).state());
 }
 @Test void aLongNameIsCutToAShortOne(){
  var long200="x".repeat(200);
  when(dashboard.getModuleStatuses()).thenReturn(List.of(new ModuleStatus(long200,"code","d","ready","ok")));
  when(controls.policy(long200)).thenReturn(new ModuleControlService.Policy("p",true,1,List.of(long200)));
  var module=((List<?>)card("scanner_modules",null).facts().get("modules")).getFirst().toString();
  assertFalse(module.contains("x".repeat(41)));
 }
 @Test @SuppressWarnings("unchecked") void textInsideAListIsRedactedAndAnUnfilledCardAddsNoBlankLine(){
  var nested=new ContextProvider(){
   @Override public String kind(){return "jobs";}
   @Override public Set<String> grants(){return Set.of();}
   @Override public ContextCard resolve(ContextRequest.Ids ids){return ContextCard.ok("jobs","Page · Jobs",Map.of("recent_failures",List.of(Map.of("error","token=abc123def456abc123def456abc123def456 failed"))),Map.of());}
  };
  var service=new ContextService(fx.access,fx.settings,List.of(nested));
  var card=service.forSubmit("alice",page("jobs",null));
  assertFalse(card.toString().contains("abc123def456abc123def456"));
  assertTrue(service.preview("alice",page("jobs",null)).lines().isEmpty(),"no 'null failed' line");
 }
 @Test void aCardThatCannotBeBuiltIsUnavailableAndChatCarriesOn(){
  when(digests.currentCounts()).thenThrow(new IllegalStateException("metrics warming up"));
  assertEquals(ContextCard.UNAVAILABLE,card("home",null).state());
 }
}

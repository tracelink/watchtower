package com.tracelink.appsec.watchtower.core.rule.report;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.persistence.RuleHealthEntity;
import com.tracelink.appsec.watchtower.core.rule.*;

class RuleReviewReportTest {
 static final LocalDate TODAY=LocalDate.of(2026,10,12);
 static Map<String,Object> health(long findings,long selected,long failed,long skipped,List<String> chips){
  Map<String,Object> h=new LinkedHashMap<>();h.put("findings",findings);h.put("selected_scans",selected);h.put("failed_scans",failed);h.put("skipped_scans",skipped);h.put("unknown_scans",0L);h.put("successful_engine_scans",Math.max(0,selected-failed-skipped));
  h.put("reviewed_sample",8L);h.put("fp",6L);h.put("reviewed_fp_rate",.75);h.put("chips",chips);return h;
 }
 static RuleReviewReport.RuleFacts facts(long id,String module,RuleState state,String owner,LocalDate reviewBy,String cwe,Set<String> languages,Map<String,Object> h90,Map<String,Object> h30,long openReviews){
  return new RuleReviewReport.RuleFacts(id,"rule-"+id,module,RulePriority.MEDIUM,state,owner,reviewBy,cwe,languages,h90,h30,openReviews);
 }
 @SuppressWarnings("unchecked") static List<Map<String,Object>> list(Object value){return (List<Map<String,Object>>)value;}
 static List<String> reasons(Map<String,Object> item){return list(item.get("reasons")).stream().map(r->(String)r.get("code")).toList();}

 @Test void attentionListRanksEvidenceAndNeverTurnsMissingDataIntoRetirementSignals(){
  var healthy=health(4,10,0,0,List.of());
  var rules=List.of(
   facts(1,"eslint",RuleState.ACTIVE,"team-a",TODAY.plusDays(30),"CWE-79",Set.of(),health(12,10,0,0,List.of("Needs review")),healthy,1),
   facts(2,"pmd",RuleState.ACTIVE,"team-b",TODAY.minusDays(1),"CWE-89",Set.of("java"),healthy,healthy,0),
   facts(3,"regex",RuleState.ACTIVE," ",null,"CWE-798",Set.of(),healthy,healthy,0),
   facts(4,"checkov",RuleState.DEPRECATED,"team-c",null,null,Set.of(),health(0,9,0,0,List.of("No recent matches")),health(0,3,0,0,List.of()),0),
   facts(5,"json",RuleState.ACTIVE,"team-d",null,"CWE-20",Set.of(),health(0,0,0,0,List.of("No recent matches","Insufficient data/coverage")),health(0,0,0,0,List.of()),0),
   facts(6,"pmd",RuleState.RETIRED,null,TODAY.minusDays(9),null,Set.of("java"),healthy,healthy,0));
  var report=RuleReviewReport.build(rules,RuleReviewReport.Catalog.load(),TODAY);
  var items=list(report.get("attention"));
  assertEquals(List.of(1L,2L,3L,4L),items.stream().map(i->((Number)i.get("rule_id")).longValue()).toList(),"noise, overdue, no owner, then zero matches; retired and data-poor rules excluded");
  assertEquals(List.of("CONFIRMED_NOISE"),reasons(items.get(0)));assertEquals(1L,((Number)items.get(0).get("open_reviews")).longValue());
  assertEquals(.75,((Number)list(items.get(0).get("reasons")).getFirst().get("reviewed_fp_rate")).doubleValue());
  assertEquals(List.of("REVIEW_OVERDUE"),reasons(items.get(1)));assertEquals(List.of("NO_OWNER"),reasons(items.get(2)));
  assertEquals(List.of("NO_RECENT_MATCHES","NO_CWE"),reasons(items.get(3)));
  assertTrue(((String)list(items.get(3).get("reasons")).getFirst().get("note")).contains("not a retirement signal"));
  @SuppressWarnings("unchecked") var counts=(Map<String,Object>)report.get("counts");
  assertEquals(5L,((Number)counts.get("rules")).longValue());assertEquals(1L,((Number)counts.get("insufficient_data")).longValue());assertEquals(1L,((Number)counts.get("retired_excluded")).longValue());
 }
 @Test void coverageMatrixKeepsTopTwentyFiveGapsVisibleAndLabelsSelectionHonestly(){
  var ran=health(3,4,1,0,List.of());var failed=health(0,2,1,1,List.of());
  var rules=List.of(
   facts(1,"eslint",RuleState.ACTIVE,"a",null,"CWE-79",Set.of(),ran,ran,0),
   facts(2,"opengrep",RuleState.ACTIVE,"a",null,"CWE-79",Set.of("python","javascript"),failed,failed,0),
   facts(3,"pmd",RuleState.ACTIVE,"a",null,"CWE-1004",Set.of("java"),ran,ran,0),
   facts(4,"regex",RuleState.ACTIVE,"a",null,null,Set.of(),ran,ran,0),
   facts(5,"pmd",RuleState.RETIRED,"a",null,"CWE-89",Set.of("java"),ran,ran,0),
   facts(6,"eslint",RuleState.ACTIVE,"a",null," cwe-79 ",Set.of(),failed,failed,0));
  @SuppressWarnings("unchecked") var matrix=(Map<String,Object>)RuleReviewReport.build(rules,RuleReviewReport.Catalog.load(),TODAY).get("matrix");
  assertEquals("2024",matrix.get("cwe_edition"));assertEquals(List.of("any","java","javascript","python"),matrix.get("languages"));
  var rows=list(matrix.get("rows"));assertEquals(27,rows.size());
  assertEquals("CWE-79",rows.get(0).get("cwe"));assertEquals(1,((Number)rows.get(0).get("rank")).intValue());
  @SuppressWarnings("unchecked") var xss=(Map<String,Map<String,Object>>)rows.get(0).get("cells");
  assertEquals(3L,((Number)xss.get("javascript").get("rules")).longValue(),"legacy cwe-79 joins the catalog row");assertEquals(1L,((Number)xss.get("javascript").get("ran_30d")).longValue());
  assertEquals(1L,((Number)xss.get("python").get("rules")).longValue());assertEquals(0L,((Number)xss.get("python").get("ran_30d")).longValue());
  var sqli=rows.stream().filter(r->"CWE-89".equals(r.get("cwe"))).findFirst().orElseThrow();assertTrue(((Map<?,?>)sqli.get("cells")).isEmpty(),"retired rules never count as coverage");
  assertEquals("CWE-1004",rows.get(25).get("cwe"));assertNull(rows.get(25).get("rank"));
  assertEquals("Unclassified",rows.get(26).get("cwe"));assertTrue(((String)matrix.get("note")).contains("not proof"));
  Set<String> many=new HashSet<>();for(int i=0;i<25;i++)many.add("lang"+i);
  @SuppressWarnings("unchecked") var capped=(Map<String,Object>)RuleReviewReport.build(List.of(facts(9,"opengrep",RuleState.ACTIVE,"a",null,"CWE-79",many,ran,ran,0)),RuleReviewReport.Catalog.load(),TODAY).get("matrix");
  @SuppressWarnings("unchecked") var columns=(List<String>)capped.get("languages");assertEquals(21,columns.size());assertTrue(columns.contains("other"));
 }

 static FeedbackThemes.Signal signal(long rule,String source,String category,String id,String actor,long at,String text){return new FeedbackThemes.Signal(rule,source,category,id,actor,at,text);}
 @Test void feedbackThemesGroupRepeatedHumanSignalsAndKeepOnlySafeSharedTerms(){
  var signals=new ArrayList<FeedbackThemes.Signal>();
  for(int i=0;i<4;i++)signals.add(signal(1,"finding_feedback","TEST_CODE","occ"+i,"reviewer"+(i%2),1000+i,i<2?"Matches fixture data in unit tests; token ghp_AbC123secret":"Only fixture builders in the unit test folder"));
  for(int i=0;i<2;i++)signals.add(signal(1,"finding_feedback","NOT_EXPLOITABLE","n"+i,"reviewer",2000,"sanitised upstream"));
  for(int i=0;i<3;i++)signals.add(signal(2,"bypass","FALSE_POSITIVE","b"+i,"dev"+i,3000+i,"generated client code /src/gen/Client.java"));
  for(int i=0;i<3;i++)signals.add(signal(3,"review_outcome","REJECTED:noise","r"+i,"owner",500,null));
  var themes=FeedbackThemes.build(signals);
  assertEquals(3,themes.size(),"groups below three records are not themes");
  var first=themes.getFirst();assertEquals(1L,((Number)first.get("rule_id")).longValue());assertEquals("finding_feedback",first.get("source"));assertEquals("TEST_CODE",first.get("category"));
  assertEquals(4L,((Number)first.get("records")).longValue());assertEquals(2L,((Number)first.get("people")).longValue());assertEquals(1003L,((Number)first.get("last_at")).longValue());
  @SuppressWarnings("unchecked") var terms=(List<String>)first.get("terms");
  assertTrue(terms.containsAll(List.of("fixture","unit")),terms.toString());
  assertTrue(terms.stream().noneMatch(t->t.contains("ghp")||t.contains("secret")||t.contains("123")),"single-record or alphanumeric words never become terms");
  assertTrue(terms.size()<=5);assertEquals(4,((List<?>)first.get("evidence")).size());
  @SuppressWarnings("unchecked") var bypassTerms=(List<String>)themes.stream().filter(t->"bypass".equals(t.get("source"))).findFirst().orElseThrow().get("terms");
  assertTrue(bypassTerms.containsAll(List.of("generated","client")));assertFalse(bypassTerms.contains("src"),"path fragments shorter than three letters or stopwords are excluded");
  assertEquals(List.of(),themes.stream().filter(t->"review_outcome".equals(t.get("source"))).findFirst().orElseThrow().get("terms"));
  var fingerprint=(String)first.get("fingerprint");assertTrue(fingerprint.matches("[0-9a-f]{64}"));
  assertEquals(fingerprint,FeedbackThemes.build(signals).getFirst().get("fingerprint"),"an unchanged theme keeps its fingerprint, so its AI name is reused");
  var grown=new ArrayList<>(signals);grown.add(signal(1,"finding_feedback","TEST_CODE","occ9","reviewer9",1009,"fixture data"));
  assertNotEquals(fingerprint,FeedbackThemes.build(grown).getFirst().get("fingerprint"),"a new record changes the fingerprint");
  var many=new ArrayList<FeedbackThemes.Signal>();for(int r=0;r<150;r++)for(int i=0;i<3;i++)many.add(signal(r+10,"bypass","OTHER","x"+r+"-"+i,"a",r,"x"));
  assertEquals(FeedbackThemes.MAX_THEMES,FeedbackThemes.build(many).size());
 }

 R1Database database;RuleReviewReportService service;RuleService rules;final AtomicReference<Instant> now=new AtomicReference<>();
 @BeforeEach void setup(){
  database=new R1Database();rules=mock(RuleService.class);
  Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  service=database.service(new RuleReviewReportService(database.records,database.repository(RuleReviewReportSettingsRepository.class),database.repository(RuleReviewReportRepository.class),rules,clock));
  now.set(TODAY.atTime(9,0).toInstant(ZoneOffset.UTC));
 }
 @AfterEach void close(){if(database!=null)database.close();}
 RuleDto rule(long id,String module,String cwe,boolean stale)throws Exception{
  var dto=mock(RuleDto.class);var stewardship=new RuleStewardship();stewardship.setOwner("team");stewardship.setCwe(cwe);
  when(dto.getId()).thenReturn(id);when(dto.getName()).thenReturn("rule-"+id);when(dto.getModule()).thenReturn(module);when(dto.getPriority()).thenReturn(RulePriority.HIGH);
  when(dto.getStewardship()).thenReturn(stewardship);when(dto.getRevision()).thenReturn("a".repeat(64));
  database.records.save(new RuleHealthEntity(id,"a".repeat(64),stale?0L:now.get().toEpochMilli(),AssistantState.mapper().writeValueAsString(Map.of("30d",health(1,2,0,0,List.of()),"90d",health(9,5,0,0,List.of("Needs review"))))));
  return dto;
 }
 @Test void weeklyReportRunsOnceOnOrAfterTheConfiguredDayAndManualRunsCannotEvictIt()throws Exception{
  var noisy=rule(7,"regex","CWE-79",false);var stale=rule(8,"pmd","CWE-89",true);when(rules.getRules()).thenReturn(List.of(noisy,stale));
  database.jdbc.update("INSERT INTO rule_review_items(review_id,rule_id,revision,owner,status,reason,recommendation,outcome,created_at,updated_at,version) VALUES (?,?,?,?,?,?,?,?,0,0,1)",UUID.randomUUID().toString(),7,"a".repeat(64),"team","OPEN","noise","Check reviewed false positives","");
  long fresh=TODAY.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC).toEpochMilli();
  for(int i=0;i<5;i++)database.jdbc.update("INSERT INTO finding_feedback(occurrence_key,scan_type,scan_id,finding_key,rule_id,revision,occurred_at,judgment,disposition,explanation,reviewer,updated_at,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
    "o".repeat(63)+i,"pull_request",i,"k"+i,7,"a".repeat(64),fresh,i==4?"TRUE_POSITIVE":"FALSE_POSITIVE","TEST_CODE","matches fixture data",i<2?"alice":"bob",i==3?fresh-100L*86400000:fresh);
  for(int i=0;i<3;i++){
   database.jdbc.update("INSERT INTO pull_request_bypasses(bypass_id,api_label,repo_name,pr_id,scan_id,bypassed_by,reason,created_at,reason_code) VALUES (?,?,?,?,?,?,?,?,?)",500+i,"local","repo","42",9,"dev"+i,"generated client stubs",fresh,"TEST_CODE");
   // Two findings of one bypass still count once.
   for(int f=0;f<2;f++)database.jdbc.update("INSERT INTO bypass_finding_identity(bypass_id,finding_id,rule_id,revision) VALUES (?,?,?,?)",500+i,600+i*2+f,7,"a".repeat(64));
   database.jdbc.update("INSERT INTO rule_review_items(review_id,rule_id,revision,owner,status,reason,recommendation,outcome,created_at,updated_at,version) VALUES (?,?,?,?,?,?,?,?,0,?,1)",UUID.randomUUID().toString(),8,"a".repeat(64),"owner","REJECTED","noise","Narrow it","kept as is",fresh);
  }
  service.change(true,2,0,"admin");
  service.scheduled();assertNull(service.latest().get("report"),"Monday is before the configured Tuesday");
  now.set(TODAY.plusDays(1).atTime(9,0).toInstant(ZoneOffset.UTC));service.scheduled();service.scheduled();
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports",Integer.class));
  @SuppressWarnings("unchecked") var report=(Map<String,Object>)service.latest().get("report");assertEquals("SCHEDULED",report.get("trigger"));assertEquals("2026-W42",report.get("period"));
  @SuppressWarnings("unchecked") var summary=(Map<String,Object>)report.get("summary");var items=list(summary.get("attention"));
  assertEquals(List.of(7L),items.stream().map(i->((Number)i.get("rule_id")).longValue()).toList(),"stale evidence is treated as missing, not as noise");
  assertEquals(List.of("CONFIRMED_NOISE"),reasons(items.getFirst()));assertEquals(1L,((Number)items.getFirst().get("open_reviews")).longValue());
  var themes=list(summary.get("themes"));assertEquals(3,themes.size());
  var feedback=themes.stream().filter(t->"finding_feedback".equals(t.get("source"))).findFirst().orElseThrow();assertEquals("TEST_CODE",feedback.get("category"));assertEquals("rule-7",feedback.get("name"));
  assertEquals(3L,((Number)feedback.get("records")).longValue(),"the 100-day-old judgment is outside the window and the TRUE_POSITIVE is not a theme input");
  var bypass=themes.stream().filter(t->"bypass".equals(t.get("source"))).findFirst().orElseThrow();assertEquals(3L,((Number)bypass.get("records")).longValue());assertEquals(List.of("client","generated","stub"),bypass.get("terms"));
  assertEquals("REJECTED:noise",themes.stream().filter(t->"review_outcome".equals(t.get("source"))).findFirst().orElseThrow().get("category"));
  @SuppressWarnings("unchecked") var counts=(Map<String,Object>)summary.get("counts");assertEquals(1L,((Number)counts.get("stale_health")).longValue());assertEquals(1L,((Number)counts.get("insufficient_data")).longValue());
  // Every pod was down on Tuesday of the next week: Thursday catches up once.
  now.set(TODAY.plusDays(10).atTime(9,0).toInstant(ZoneOffset.UTC));service.scheduled();service.scheduled();
  assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports WHERE trigger_type='SCHEDULED'",Integer.class));
  for(int i=0;i<13;i++){now.set(now.get().plus(Duration.ofMinutes(6)));service.runNow("reviewer");}
  assertEquals(12,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports WHERE trigger_type='MANUAL'",Integer.class));
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports WHERE period_key='2026-W43'",Integer.class),"manual runs never evict the weekly report");
  service.scheduled();assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports WHERE trigger_type='SCHEDULED'",Integer.class));
  assertEquals(429,assertThrows(ResponseStatusException.class,()->service.runNow("reviewer")).getStatusCode().value());
 }
 @Test void fullAttentionRowsStayReachableBeyondSummaryCapAndLegacyStaysExplicit()throws Exception{
  var backlog=new ArrayList<RuleDto>();
  for(long id=1;id<=507;id++){var dto=mock(RuleDto.class);when(dto.getId()).thenReturn(id);when(dto.getName()).thenReturn(id==507?"literal%":"rule-"+id);when(dto.getModule()).thenReturn("regex");when(dto.getStewardship()).thenReturn(new RuleStewardship());when(dto.getRevision()).thenReturn("a".repeat(64));backlog.add(dto);}
  when(rules.getRules()).thenReturn(backlog);String id=service.runNow("reviewer");
  var page=service.attention(id,"","all",20,25);assertTrue(page.complete());assertEquals(507,page.rows().totalElements());assertEquals(7,page.rows().content().size());assertEquals(501,page.rows().content().getFirst().ruleId());
  assertEquals(1,service.attention(id,"%","NO_OWNER",0,25).rows().totalElements());
  assertThrows(IllegalArgumentException.class,()->service.attention(id,"","all",0,101));
  assertThrows(IllegalArgumentException.class,()->service.attention(id,"","owner=anything",0,25));
  @SuppressWarnings("unchecked")var report=(Map<String,Object>)service.saved(id).get("report");@SuppressWarnings("unchecked")var summary=(Map<String,Object>)report.get("summary");assertEquals(500,list(summary.get("attention")).size());
  when(rules.getRules()).thenReturn(List.of());assertEquals(507,service.attention(id,"","all",0,25).rows().totalElements(),"saved rows never become current data");
  String legacy=UUID.randomUUID().toString();database.records.insert(new RuleReviewReportEntity(legacy,null,"MANUAL","old",0,1,AssistantState.mapper().writeValueAsString(summary)));
  var old=service.attention(legacy,"","all",0,25);assertFalse(old.complete());assertTrue(old.legacyTruncated());assertEquals(500,old.rows().totalElements());
 }
 @Test void missingHistoricalSuccessMetadataDoesNotImplySuccessfulExecution(){
  var unknown=health(0,5,0,0,List.of());unknown.remove("successful_engine_scans");
  var report=RuleReviewReport.build(List.of(facts(1,"regex",RuleState.ACTIVE,"owner",null,"CWE-79",Set.of(),unknown,unknown,0)),RuleReviewReport.Catalog.load(),TODAY);
  assertTrue(list(report.get("attention")).isEmpty());
 }
 @Test void settingsUseOptimisticVersionsAndDisableTheSchedule()throws Exception{
  when(rules.getRules()).thenReturn(List.of());
  @SuppressWarnings("unchecked") var settings=(Map<String,Object>)service.latest().get("settings");long version=((Number)settings.get("version")).longValue();
  assertEquals(true,settings.get("enabled"));assertEquals(1,((Number)settings.get("weekday")).intValue());
  assertThrows(IllegalArgumentException.class,()->service.change(true,8,version,"reviewer"));
  service.change(false,2,version,"reviewer");
  assertEquals(409,assertThrows(ResponseStatusException.class,()->service.change(true,1,version,"other")).getStatusCode().value());
  now.set(TODAY.plusDays(1).atTime(9,0).toInstant(ZoneOffset.UTC));service.scheduled();
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_reports",Integer.class));
  assertEquals("reviewer",database.jdbc.queryForObject("SELECT updated_by FROM rule_review_report_settings",String.class));
 }
}

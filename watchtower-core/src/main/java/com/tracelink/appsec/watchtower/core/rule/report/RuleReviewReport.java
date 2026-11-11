package com.tracelink.appsec.watchtower.core.rule.report;

import java.io.IOException;
import java.time.LocalDate;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/**
 * Pure, source-free report construction from precomputed rule facts (stewardship plus the
 * rule-health rollup). It only ranks evidence for humans: nothing here opens review items, retires
 * rules or changes enforcement, and missing data is never turned into a retirement signal.
 */
public final class RuleReviewReport {
 public record RuleFacts(long id,String name,String module,RulePriority priority,RuleState state,String owner,LocalDate reviewBy,
   String cwe,Set<String> languages,Map<String,Object> health90,Map<String,Object> health30,long openReviews,String revision,boolean notSecurity) {
  public RuleFacts(long id,String name,String module,RulePriority priority,RuleState state,String owner,LocalDate reviewBy,String cwe,Set<String> languages,Map<String,Object> health90,Map<String,Object> health30,long openReviews,String revision){this(id,name,module,priority,state,owner,reviewBy,cwe,languages,health90,health30,openReviews,revision,false);}
  public RuleFacts(long id,String name,String module,RulePriority priority,RuleState state,String owner,LocalDate reviewBy,String cwe,Set<String> languages,Map<String,Object> health90,Map<String,Object> health30,long openReviews){this(id,name,module,priority,state,owner,reviewBy,cwe,languages,health90,health30,openReviews,null,false);}
 }
 public record Entry(int rank,String id,String name) { }
 /** Pinned, versioned MITRE CWE Top 25; replacing the edition is a reviewed change. */
 public record Catalog(String edition,String source,List<Entry> entries) {
  public static Catalog load(){
   try(var in=RuleReviewReport.class.getResourceAsStream("/rule-review/cwe-top25-2024.json")){return MAPPER.readValue(in,Catalog.class);}
   catch(IOException|RuntimeException e){throw new IllegalStateException("CWE Top 25 catalog unavailable",e);}
  }
 }
 static final int MAX_ATTENTION=500;
 /** Languages beyond this many share an "other" column so the stored summary stays bounded. */
 static final int MAX_LANGUAGES=20;
 static final String OTHER_LANGUAGE="other";
 static final String UNCLASSIFIED="Unclassified";
 private static final ObjectMapper MAPPER=new ObjectMapper();
 private static final List<String> REASON_ORDER=List.of("CONFIRMED_NOISE","REVIEW_OVERDUE","NO_OWNER","NO_RECENT_MATCHES","NO_CWE");
 /** Engines whose rules do not name languages; Opengrep and PMD rules report their own. */
 private static final Map<String,Set<String>> MODULE_LANGUAGES=Map.of(
  "eslint",Set.of("javascript"),"pmd",Set.of("java"),"checkov",Set.of("iac"),"json",Set.of("json/yaml"),
  "regex",Set.of("any"),"betterleaks",Set.of("any"),"advisory",Set.of("dependencies"));
 private RuleReviewReport() { }

 public static Map<String,Object> build(List<RuleFacts> rules,Catalog catalog,LocalDate today){return build(rules,List.of(),catalog,today);}
 public static Map<String,Object> build(List<RuleFacts> rules,List<FeedbackThemes.Signal> signals,Catalog catalog,LocalDate today){
  var live=rules.stream().filter(r->r.state()!=RuleState.RETIRED).toList();
  var attention=attention(rules,today);
  long insufficient=live.stream().filter(r->health(r.health90()).isEmpty()||chips(r.health90()).contains(RuleHealthService.INSUFFICIENT_DATA)).count();
  Map<String,Object> counts=new LinkedHashMap<>();
  counts.put("rules",(long)live.size());counts.put("retired_excluded",(long)(rules.size()-live.size()));counts.put("insufficient_data",insufficient);counts.put("attention",(long)attention.size());
  Map<String,Object> report=new LinkedHashMap<>();
  report.put("generated_on",today.toString());report.put("counts",counts);
  report.put("attention",attention.size()>MAX_ATTENTION?List.copyOf(attention.subList(0,MAX_ATTENTION)):attention);report.put("attention_truncated",attention.size()>MAX_ATTENTION);
  report.put("matrix",matrix(live,catalog));
  Map<Long,RuleFacts> byId=new HashMap<>();rules.forEach(r->byId.put(r.id(),r));
  var themes=FeedbackThemes.build(signals).stream().map(t->{Map<String,Object> theme=new LinkedHashMap<>(t);var rule=byId.get((Long)t.get("rule_id"));
   theme.put("name",rule==null?null:rule.name());theme.put("module",rule==null?null:rule.module());return theme;}).toList();
  report.put("themes",themes);counts.put("themes",(long)themes.size());
  report.put("themes_note","Suggestions from repeated human feedback in the last 90 days. Raw judgments are unchanged and themes do not affect rule health.");
  return report;
 }

 /** Complete attention rows; the JSON summary is deliberately a separate bounded sample. */
 public static List<Map<String,Object>> attention(List<RuleFacts> rules,LocalDate today){
  List<Map<String,Object>> result=new ArrayList<>();
  for(var rule:rules)if(rule.state()!=RuleState.RETIRED){var reasons=reasons(rule,today);if(!reasons.isEmpty())result.add(item(rule,reasons));}
  result.sort(Comparator.comparingInt((Map<String,Object> i)->(int)i.get("severity")).thenComparingInt(i->(int)i.get("priority_order")).thenComparingLong(i->(long)i.get("rule_id")));
  return result;
 }
 private static List<Map<String,Object>> reasons(RuleFacts rule,LocalDate today){
  List<Map<String,Object>> reasons=new ArrayList<>();var h90=health(rule.health90());
  if(chips(h90).contains(RuleHealthService.NEEDS_REVIEW)){var r=reason("CONFIRMED_NOISE");r.put("window","90d");r.put("reviewed_sample",n(h90,"reviewed_sample"));r.put("false_positives",n(h90,"fp"));r.put("reviewed_fp_rate",h90.get("reviewed_fp_rate"));reasons.add(r);}
  if(rule.reviewBy()!=null&&rule.reviewBy().isBefore(today)){var r=reason("REVIEW_OVERDUE");r.put("review_by",rule.reviewBy().toString());reasons.add(r);}
  if(blank(rule.owner()))reasons.add(reason("NO_OWNER"));
  if(!h90.isEmpty()&&n(h90,"findings")==0&&completed(h90)>0){
   var r=reason("NO_RECENT_MATCHES");r.put("window","90d");r.put("completed_selections",completed(h90));
   r.put("note","Informational: zero matches can mean the risk is absent from scanned code. This is not a retirement signal.");reasons.add(r);
  }
  if(blank(rule.cwe())&&!rule.notSecurity())reasons.add(reason("NO_CWE"));
  return reasons;
 }
 private static Map<String,Object> item(RuleFacts rule,List<Map<String,Object>> reasons){
  Map<String,Object> item=new LinkedHashMap<>();
  item.put("rule_id",rule.id());item.put("revision",rule.revision());item.put("name",rule.name());item.put("module",rule.module());
  item.put("priority",rule.priority()==null?null:rule.priority().name());item.put("priority_order",rule.priority()==null?Integer.MAX_VALUE:rule.priority().ordinal());
  item.put("owner",blank(rule.owner())?null:rule.owner().trim());item.put("open_reviews",rule.openReviews());
  item.put("severity",REASON_ORDER.indexOf((String)reasons.getFirst().get("code")));item.put("reasons",reasons);return item;
 }
 private static Map<String,Object> matrix(List<RuleFacts> everyRule,Catalog catalog){
  // A rule marked "not a security rule" has no CWE by design, so it is not part of the CWE picture.
  List<RuleFacts> live=everyRule.stream().filter(rule->!rule.notSecurity()).toList();
  SortedSet<String> languages=new TreeSet<>();Map<String,Map<String,long[]>> cells=new HashMap<>();
  Map<String,Long> popularity=new HashMap<>();for(var rule:live)for(var language:languages(rule))popularity.merge(language,1L,Long::sum);
  Set<String> kept=new HashSet<>(popularity.keySet().stream().sorted(Comparator.comparingLong((String l)->-popularity.get(l)).thenComparing(Comparator.naturalOrder())).limit(MAX_LANGUAGES).toList());
  for(var rule:live){
   String cwe=normalizeCwe(rule.cwe());boolean ran=completed(health(rule.health30()))>0;
   for(var language:new TreeSet<>(languages(rule).stream().map(l->kept.contains(l)?l:OTHER_LANGUAGE).toList())){languages.add(language);var counts=cells.computeIfAbsent(cwe,k->new TreeMap<>()).computeIfAbsent(language,k->new long[2]);counts[0]++;if(ran)counts[1]++;}
  }
  List<Map<String,Object>> rows=new ArrayList<>();
  catalog.entries().stream().sorted(Comparator.comparingInt(Entry::rank)).forEach(e->rows.add(row(e.id(),e.rank(),e.name(),cells.remove(e.id()))));
  var unclassified=cells.remove(UNCLASSIFIED);
  cells.keySet().stream().sorted(Comparator.comparingLong(RuleReviewReport::cweNumber).thenComparing(Comparator.naturalOrder())).forEach(cwe->rows.add(row(cwe,null,null,cells.get(cwe))));
  rows.add(row(UNCLASSIFIED,null,"Rules without a CWE",unclassified));
  Map<String,Object> matrix=new LinkedHashMap<>();
  matrix.put("cwe_edition",catalog.edition());matrix.put("cwe_source",catalog.source());matrix.put("languages",new ArrayList<>(languages));matrix.put("rows",rows);
  matrix.put("note","A rule in a cell is not proof of comprehensive coverage. \"Ran\" means the rule was selected in a scan its module completed in the last 30 days; per-rule evaluation is not certified.");
  return matrix;
 }
 private static Map<String,Object> row(String cwe,Integer rank,String name,Map<String,long[]> counts){
  Map<String,Object> row=new LinkedHashMap<>();row.put("cwe",cwe);row.put("rank",rank);row.put("name",name);
  Map<String,Map<String,Object>> cells=new TreeMap<>();
  if(counts!=null)counts.forEach((language,c)->cells.put(language,Map.of("rules",c[0],"ran_30d",c[1])));
  row.put("cells",cells);return row;
 }
 private static Set<String> languages(RuleFacts rule){
  if(rule.languages()!=null&&!rule.languages().isEmpty())return rule.languages().stream().map(l->l.trim().toLowerCase(Locale.ROOT)).filter(l->!l.isEmpty()).collect(java.util.stream.Collectors.toSet());
  return MODULE_LANGUAGES.getOrDefault(rule.module()==null?"":rule.module().toLowerCase(Locale.ROOT),Set.of("unknown"));
 }
 /** Selections in scans whose module did not fail or skip; per-rule coverage may remain unknown. */
 private static long completed(Map<String,Object> h){return n(h,"successful_engine_scans");}
 /** Legacy spellings such as "cwe-79" or "CWE 79" join the canonical catalog row. */
 public static String normalizeCwe(String cwe){
  if(blank(cwe))return UNCLASSIFIED;var m=java.util.regex.Pattern.compile("(?i)\\s*(?:cwe)?[-_ ]*0*([1-9][0-9]{0,8})\\s*").matcher(cwe);
  return m.matches()?"CWE-"+m.group(1):cwe.trim().toUpperCase(Locale.ROOT);
 }
 private static long cweNumber(String cwe){try{return Long.parseLong(cwe.substring(cwe.indexOf('-')+1));}catch(RuntimeException e){return Long.MAX_VALUE;}}
 private static Map<String,Object> reason(String code){Map<String,Object> r=new LinkedHashMap<>();r.put("code",code);return r;}
 private static Map<String,Object> health(Map<String,Object> h){return h==null?Map.of():h;}
 private static List<?> chips(Map<String,Object> h){return h!=null&&h.get("chips") instanceof List<?> list?list:List.of();}
 private static long n(Map<String,Object> h,String key){return h!=null&&h.get(key) instanceof Number number?number.longValue():0;}
 private static boolean blank(String value){return value==null||value.isBlank();}
}

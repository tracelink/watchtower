package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Deterministic grouping of repeated human feedback (plan R5.2). Themes are suggestions shown in
 * the review report; raw judgments, bypasses and review outcomes are never changed, and themes
 * are not health inputs. Only alphabetic words shared by several records are surfaced as terms,
 * so tokens, code and paths cannot pass through.
 */
public final class FeedbackThemes {
 /** One human record: a false-positive judgment, a PR bypass or a decided review. */
 public record Signal(long ruleId,String source,String category,String id,String actor,long at,String text) { }
 static final int MIN_RECORDS=3,MAX_THEMES=100,MAX_TERMS=5,MAX_EVIDENCE=10,MIN_TERM_RECORDS=2;
 private static final Pattern WORD=Pattern.compile("[a-z]{3,24}");
 private static final Pattern SPLIT=Pattern.compile("[^A-Za-z0-9_]+");
 private static final Set<String> STOPWORDS=Set.of("the","and","for","are","but","not","you","all","any","can","had","her","was","one","our","out",
  "has","have","this","that","with","from","they","been","were","which","their","there","when","what","only","into","than","then","them",
  "also","just","more","some","such","very","will","would","should","could","because","does","doesn","isn","its","here","these",
  "those","over","under","about","after","before","rule","finding","findings","code","file","files","src","main","java","line");
 private FeedbackThemes() { }

 public static List<Map<String,Object>> build(List<Signal> signals){
  Map<String,List<Signal>> groups=new LinkedHashMap<>();
  for(var s:signals)groups.computeIfAbsent(s.ruleId()+"\u0000"+s.source()+"\u0000"+s.category(),k->new ArrayList<>()).add(s);
  List<Map<String,Object>> themes=new ArrayList<>();
  for(var group:groups.values()){
   if(group.size()<MIN_RECORDS)continue;
   var first=group.getFirst();var ordered=group.stream().sorted(Comparator.comparingLong(Signal::at).reversed().thenComparing(Signal::id)).toList();
   Map<String,Object> theme=new LinkedHashMap<>();
   theme.put("rule_id",first.ruleId());theme.put("source",first.source());theme.put("category",first.category());
   theme.put("records",(long)group.size());theme.put("people",group.stream().map(Signal::actor).filter(Objects::nonNull).distinct().count());
   theme.put("first_at",group.stream().mapToLong(Signal::at).min().orElse(0));theme.put("last_at",ordered.getFirst().at());
   var evidence=ordered.stream().limit(MAX_EVIDENCE).map(Signal::id).toList();
   theme.put("terms",terms(group));theme.put("evidence",evidence);theme.put("fingerprint",fingerprint(first,group.size(),evidence));
   themes.add(theme);
  }
  themes.sort(Comparator.comparingLong((Map<String,Object> t)->-(long)t.get("records")).thenComparingLong(t->-(long)t.get("last_at")).thenComparingLong(t->(long)t.get("rule_id")));
  return themes.size()>MAX_THEMES?List.copyOf(themes.subList(0,MAX_THEMES)):themes;
 }
 /**
  * Identifies a theme across reports for R5.2b naming: the same rule, source, category, record
  * count and newest evidence give the same fingerprint, so an unchanged theme keeps its name.
  */
 static String fingerprint(Signal first,int records,List<String> evidence){
  try{
   var digest=java.security.MessageDigest.getInstance("SHA-256");
   for(String part:List.of(Long.toString(first.ruleId()),first.source(),first.category(),Integer.toString(records),String.join("\u0001",evidence)))
    {digest.update(part.getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);}
   return java.util.HexFormat.of().formatHex(digest.digest());
  }catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}
 }
 /** Words shared by at least two records of the group, most common first. */
 private static List<String> terms(List<Signal> group){
  Map<String,Integer> records=new HashMap<>();
  for(var s:group){
   if(s.text()==null)continue;Set<String> words=new HashSet<>();
   for(var token:SPLIT.split(s.text()))if(!token.isEmpty()&&token.chars().allMatch(Character::isLetter)){var word=token.toLowerCase(Locale.ROOT);if(WORD.matcher(word).matches()&&!STOPWORDS.contains(word))words.add(stem(word));}
   words.forEach(w->records.merge(w,1,Integer::sum));
  }
  return records.entrySet().stream().filter(e->e.getValue()>=MIN_TERM_RECORDS)
   .sorted(Map.Entry.<String,Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey())).limit(MAX_TERMS).map(Map.Entry::getKey).toList();
 }
 /** Folds simple plurals so "tests" and "test" count together. */
 private static String stem(String word){return word.length()>4&&word.endsWith("s")&&!word.endsWith("ss")?word.substring(0,word.length()-1):word;}
}

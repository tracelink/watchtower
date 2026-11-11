package com.tracelink.appsec.watchtower.core.assistant.context;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSettingsService;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;

/**
 * Turns the page ids the browser sent into a card the server trusts: re-resolved for this person,
 * grant-checked, secret-checked and bounded. Nothing the page says about itself is used.
 */
@Service
public class ContextService {
 private static final Logger LOG=LoggerFactory.getLogger(ContextService.class);
 /** The most a card may add to a model request. */
 public static final int MAX_CARD_BYTES=2048,MAX_TITLE=160;
 private final AssistantAccess access;private final AssistantSettingsService settings;private final Map<String,ContextProvider> providers=new LinkedHashMap<>();
 public ContextService(AssistantAccess access,AssistantSettingsService settings,List<ContextProvider> providers){
  this.access=access;this.settings=settings;providers.forEach(p->this.providers.put(p.kind(),p));
 }
 /** The card for a new turn, or null when the page sent none or context cards are switched off. */
 public ContextCard forSubmit(String owner,ContextRequest request){
  if(request==null||!settings.get().settings().isFeatureOn(AssistantFeature.CONTEXT_CARDS))return null;
  if(request.v()==null||request.v()!=ContextRequest.VERSION||request.ids()==null)return ContextCard.unavailable(request.kind());
  var provider=providers.get(request.kind());
  if(provider==null)return ContextCard.unavailable(request.kind());
  return resolve(owner,provider,request.ids(),false);
 }
 /** What the drawer's chip shows before anything is asked: how the server understood the page, in a few words. */
 public record Preview(String state,String label,String title,List<String> lines) { }
 public Preview preview(String owner,ContextRequest request){
  var card=forSubmit(owner,request);
  if(card==null)return new Preview("NONE",null,null,List.of());
  if(!card.isOk())return new Preview(card.state(),null,null,List.of());
  return new Preview(card.state(),AssistantText.redact(labelOf(card)),card.title(),summaryLines(card));
 }
 /** The chip text: the rule and the file for a finding, else the card title without its kind. */
 static String labelOf(ContextCard card){
  if("finding".equals(card.kind())&&card.facts().get("rule") instanceof Map<?,?> rule&&rule.get("name") instanceof String name){
   String where=card.facts().get("path") instanceof String path?" · "+path.substring(path.lastIndexOf('/')+1)+(card.facts().get("line") instanceof Number line?":"+line:""):"";
   return name+where;
  }
  int dot=card.title().indexOf(" · ");return dot<0?card.title():card.title().substring(dot+3);
 }
 private static final Map<String,String> JUDGMENTS=Map.of("NONE","Not reviewed","TRUE_POSITIVE","True positive","FALSE_POSITIVE","False positive");
 /** Up to four plain lines for the chip's hover; nothing here is text a scanner or a person wrote. */
 static List<String> summaryLines(ContextCard card){
  var f=card.facts();var lines=new ArrayList<String>();
  switch(card.kind()){
   case "finding"->{
    lines.add(join(" · ",f.get("severity"),f.get("repository")));
    lines.add(JUDGMENTS.getOrDefault(String.valueOf(f.get("judgment")),"Reviewed")+" · "+(Boolean.TRUE.equals(f.get("assessment_available"))?"AI assessment available":"no AI assessment yet"));
    if(f.get("path") instanceof String path)lines.add(path+(f.get("line") instanceof Number line?" line "+line:""));
   }
   case "repository"->{lines.add(join(" · ",f.get("integration"),f.get("language")));if(f.get("ruleset")!=null)lines.add("Ruleset "+f.get("ruleset"));}
   case "pull_request"->{
    lines.add(join(" · ",f.get("repository"),f.get("pull_request")==null?null:"#"+f.get("pull_request")));
    lines.add(Boolean.TRUE.equals(f.get("blocked"))?"Blocking the merge":"Not blocking");
   }
   case "rule"->lines.add(join(" · ",f.get("engine"),f.get("state")));
   case "home"->{
    if(f.get("this_week") instanceof Map<?,?> week&&week.get("scans_finished")!=null&&week.get("findings")!=null)lines.add("Last 7 days: "+count(week.get("scans_finished"),"scan","scans")+" · "+count(week.get("findings"),"finding","findings"));
    if(f.get("now") instanceof Map<?,?> now&&now.get("integrations_failing")!=null)lines.add(count(now.get("integrations_failing"),"integration","integrations")+" failing");
   }
   case "repositories"->{if(has(f,"repositories","without_ruleset"))lines.add(count(f.get("repositories"),"repository","repositories")+" · "+f.get("without_ruleset")+" without a ruleset");}
   case "alert_settings"->{if(has(f,"channels","routes"))lines.add(count(f.get("channels"),"channel","channels")+" · "+count(f.get("routes"),"route","routes"));}
   case "jobs"->{if(has(f,"failed_24h","queued"))lines.add(f.get("failed_24h")+" failed in 24 h · "+f.get("queued")+" waiting");}
   case "metrics"->{if(has(f,"scans","findings"))lines.add(join(" · ",f.get("scan_type"),count(f.get("scans"),"scan","scans"),count(f.get("findings"),"finding","findings")));}
   case "scanner_modules"->{if(has(f,"ready","needs_setup","off"))lines.add(f.get("ready")+" ready · "+f.get("needs_setup")+" need setup · "+f.get("off")+" off");}
   default->{ }
  }
  lines.removeIf(String::isBlank);return List.copyOf(lines);
 }
 /** A count as people read it on the page: thousands grouped, and the noun singular for exactly one. */
 private static String count(Object value,String one,String many){
  if(!(value instanceof Number n))return value+" "+many;
  return String.format(Locale.US,"%,d",n.longValue())+" "+(n.longValue()==1?one:many);
 }
 private static boolean has(Map<String,Object> facts,String... keys){for(String key:keys)if(facts.get(key)==null)return false;return true;}
 private static String join(String separator,Object... parts){
  return Arrays.stream(parts).filter(Objects::nonNull).map(String::valueOf).filter(p->!p.isBlank()).collect(java.util.stream.Collectors.joining(separator));
 }
 /** Whether a finding named by these ids is blocked now, for tool output kept from an earlier turn. Unknown or unreadable counts as blocked. */
 public boolean findingIsBlockedNow(ContextRequest.Ids ids){
  var provider=providers.get("finding");
  if(provider==null)return true;
  try{return provider.resolve(ids).isBlocked();}catch(RuntimeException e){return true;}
 }
 /** Checks a stored card again before it is used on a turn; revoked access stops the turn. */
 public ContextCard revalidate(String owner,ContextCard stored){
  if(stored==null||!cardsOn())return stored==null?null:ContextCard.unavailable(stored.kind());
  var provider=providers.get(stored.kind());
  if(provider==null)return ContextCard.unavailable(stored.kind());
  return resolve(owner,provider,idsOf(stored),true);
 }
 private boolean cardsOn(){return settings.get().settings().isFeatureOn(AssistantFeature.CONTEXT_CARDS);}
 private ContextCard resolve(String owner,ContextProvider provider,ContextRequest.Ids ids,boolean strict){
  Set<String> held=access.authorities(owner);
  if(!held.containsAll(provider.grants())){
   if(strict)throw new AccessDeniedException("Access revoked or unavailable");
   return ContextCard.unavailable(provider.kind());
  }
  try{return bounded(provider.resolve(ids));}
  catch(RuntimeException e){
   // A card that cannot be built is never guessed at; chat carries on without it.
   LOG.warn("Context card for {} could not be built: {}",provider.kind(),e.getClass().getSimpleName());
   return ContextCard.unavailable(provider.kind());
  }
 }
 /** Free text is redacted and the card is cut down to its title and ids if it is still too large. */
 static ContextCard bounded(ContextCard card){
  var facts=new LinkedHashMap<String,Object>();
  card.facts().forEach((k,v)->facts.put(k,redactDeep(v)));
  var redacted=new ContextCard(card.kind(),card.state(),AssistantText.redact(card.title()),facts,card.ids());
  if(size(redacted)<=MAX_CARD_BYTES)return redacted;
  String title=AssistantText.redact(card.title());if(title.length()>MAX_TITLE)title=title.substring(0,MAX_TITLE);
  return new ContextCard(card.kind(),card.state(),title,Map.of("note","Details were left out to keep this short."),card.ids());
 }
 /** Free text is redacted wherever it sits, including inside the lists and maps of the newer cards. */
 static Object redactDeep(Object value){
  if(value instanceof String text)return AssistantText.redact(text);
  if(value instanceof Map<?,?> map){var copy=new LinkedHashMap<Object,Object>();map.forEach((k,v)->copy.put(k,redactDeep(v)));return copy;}
  if(value instanceof List<?> list)return list.stream().map(ContextService::redactDeep).toList();
  return value;
 }
 static int size(ContextCard card){
  try{return AssistantState.mapper().writeValueAsString(card).getBytes(StandardCharsets.UTF_8).length;}
  catch(JsonProcessingException e){throw new IllegalStateException("Context card could not be written",e);}
 }
 /** Rebuilds the ids a stored card was made from. */
 static ContextRequest.Ids idsOf(ContextCard card){
  var ids=card.ids();
  return new ContextRequest.Ids((String)ids.get("scanType"),number(ids.get("scanId")),(String)ids.get("findingKey"),number(ids.get("repoId")),number(ids.get("ruleId")));
 }
 private static Long number(Object value){return value instanceof Number n?n.longValue():null;}
 /** The ids of a request as card ids, with only the ones that are set. */
 public static Map<String,Object> idMap(ContextRequest.Ids ids){
  var map=new LinkedHashMap<String,Object>();
  if(ids.scanType()!=null)map.put("scanType",ids.scanType());
  if(ids.scanId()!=null)map.put("scanId",ids.scanId());
  if(ids.findingKey()!=null)map.put("findingKey",ids.findingKey());
  if(ids.repoId()!=null)map.put("repoId",ids.repoId());
  if(ids.ruleId()!=null)map.put("ruleId",ids.ruleId());
  return map;
 }
}

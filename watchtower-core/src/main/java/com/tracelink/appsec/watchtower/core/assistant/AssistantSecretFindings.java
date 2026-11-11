package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * Secrets found by any engine are never sent to the AI provider. A secret rule belongs to a
 * sensitive scanner (Betterleaks) or carries a credential CWE, so a Regex or Opengrep rule for a
 * hard-coded token counts too. Source lines where a stored finding of such a rule was recorded
 * are masked on every commit of that repository and path; human free text about such rules is
 * withheld because people paste the value there. Lookups fail closed.
 */
@Service
public class AssistantSecretFindings {
 /** Hard-coded credentials, hard-coded password, hard-coded key, insufficiently protected credentials. */
 public static final Set<String> SECRET_CWES=Set.of("CWE-798","CWE-259","CWE-321","CWE-522");
 public static final String WITHHELD="[withheld: this rule detects secrets]";
 private static final java.util.regex.Pattern CREDENTIAL_NAME=java.util.regex.Pattern.compile("(?i)secret|token|password|passwd|credential|api[-_ ]?key|private[-_ ]?key|access[-_ ]?key|webhook|bearer");
 static final int MAX_FINDINGS=20000,MAX_NAMES=50000,RECENT_REPO_SCANS=5;
 /** Thrown when the stored findings cannot be read completely; the caller sends nothing. */
 public static class Unavailable extends RuntimeException {
  private static final long serialVersionUID=1L;
  public Unavailable(String message){super(message);}
 }
 /** The current secret rules, by id, name and sensitive module. */
 public record SecretRules(Set<Long> ids,Set<String> names,Set<String> modules,Set<String> lowerNames) {
  public SecretRules(Set<Long> ids,Set<String> names,Set<String> modules){
   this(ids,names,modules,names.stream().map(n->n.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet()));
  }
  /** Names compare ignoring case, as the database does when it matches stored findings. */
  public boolean contains(Long ruleId,String module,String name){
   return ruleId!=null&&ids.contains(ruleId)||module!=null&&modules.contains(module.toLowerCase(Locale.ROOT))||name!=null&&lowerNames.contains(name.toLowerCase(Locale.ROOT));
  }
 }
 /** Recorded secret lines of one repository, by repository-relative path. */
 public static final class Lines {
  private final Map<String,Map<Integer,String>> byPath;
  Lines(Map<String,Map<Integer,String>> byPath){this.byPath=byPath;}
  /** The engine that recorded a secret on this line, or null. Stored paths may carry a prefix. */
  public String engine(String path,int line){
   String wanted=normalize(path);
   for(var e:byPath.entrySet())if(e.getKey().equals(wanted)||e.getKey().endsWith("/"+wanted)){String engine=e.getValue().get(line);if(engine!=null)return engine;}
   return null;
  }
  public boolean isEmpty(){return byPath.isEmpty();}
 }
 private final RuleService rules;private final ScanRegistrationService registry;private final LedgerRepository records;
 private final RepoScanRepository repoScans;private final RepoScanReportService reports;
 public AssistantSecretFindings(RuleService rules,ScanRegistrationService registry,LedgerRepository records,RepoScanRepository repoScans,RepoScanReportService reports){
  this.rules=rules;this.registry=registry;this.records=records;this.repoScans=repoScans;this.reports=reports;
 }
 public boolean isSecretRule(RuleDto rule){
  return rule!=null&&(registry.isSensitiveModule(rule.getModule())||rule.getStewardship()!=null&&SECRET_CWES.contains(RuleReviewReport.normalizeCwe(rule.getStewardship().getCwe()))||namesACredential(rule.getName()));
 }
 /**
  * A rule that has no credential CWE yet (most rules have none) can still say in its name that it finds
  * tokens, keys, passwords or webhooks. Leaning on the name errs towards withholding, which is the safe side.
  */
 static boolean namesACredential(String name){
  return name!=null&&CREDENTIAL_NAME.matcher(name).find();
 }
 public SecretRules secretRules(){
  Set<Long> ids=new HashSet<>();Set<String> names=new HashSet<>();Set<String> modules=new HashSet<>();
  for(String module:registry.getScannerNames())if(registry.isSensitiveModule(module))modules.add(module.toLowerCase(Locale.ROOT));
  for(var rule:rules.getRules())if(isSecretRule(rule)){if(rule.getId()!=null)ids.add(rule.getId());names.add(rule.getName());}
  return new SecretRules(Set.copyOf(ids),Set.copyOf(names),Set.copyOf(modules));
 }
 /** Bypasses that covered at least one finding of a secret rule: their written reasons are never sent. */
 @Transactional(readOnly=true)
 public Set<Long> bypassesCoveringSecrets(Collection<Long> bypassIds,SecretRules secret){
  if(bypassIds.isEmpty())return Set.of();Set<Long> result=new HashSet<>();var ids=List.copyOf(new HashSet<>(bypassIds));
  for(int from=0;from<ids.size();from+=500){
   var chunk=ids.subList(from,Math.min(ids.size(),from+500));
   result.addAll(records.list(Long.class,"SELECT DISTINCT v.bypassId FROM BypassFindingIdentityEntity v WHERE v.bypassId IN ?1 AND v.ruleId IN ?2",0,Integer.MAX_VALUE,chunk,nonEmpty(secret.ids(),-1L)));
   // Legacy identities without a rule id: decide by the stored finding's engine or rule name.
   result.addAll(records.list(Long.class,"SELECT DISTINCT v.bypassId FROM BypassFindingIdentityEntity v,PullRequestViolationEntity p WHERE p.id=v.findingId AND v.bypassId IN ?1"
     +" AND (LOWER(p.ruleIdentity.module) IN ?2 OR p.violationName IN ?3)",0,Integer.MAX_VALUE,chunk,nonEmpty(secret.modules(),"\u0000"),nonEmpty(secret.names(),"\u0000")));
  }
  return result;
 }
 /**
  * Whether a secret finding of any engine was recorded at this one path and line of the repository. It
  * asks the database about that line only (not every secret line of the repository) and reads the same
  * recent repository-scan reports as {@link #lines}. {@code pullRequestRepoNames} are the spellings the
  * pull request webhooks used for this repository. Fails closed with {@link Unavailable}.
  */
 @Transactional(readOnly=true)
 public boolean isRecordedSecretLine(RepositoryEntity repo,String path,int line,Collection<String> pullRequestRepoNames){
  if(repo==null||path==null||path.isBlank()||line<1)throw new Unavailable("The location cannot be checked for secrets");
  var secret=secretRules();Map<String,Map<Integer,String>> byPath=new HashMap<>();
  try{
   var names=pullRequestRepoNames.stream().filter(n->n!=null&&!n.isBlank()).distinct().toList();
   if(!names.isEmpty()){
    var rows=records.maps("SELECT v.fileName AS path,v.lineNum AS line,v.ruleIdentity.module AS module,v.violationName AS name FROM PullRequestViolationEntity v"
      +" WHERE v.lineNum=?1 AND LOWER(v.scan.container.apiLabel)=?2 AND v.scan.container.repoName IN ?3"
      +" AND (v.ruleIdentity.ruleId IN ?4 OR LOWER(v.ruleIdentity.module) IN ?5 OR v.violationName IN ?6)",0,MAX_FINDINGS+1,line,repo.getApiLabel().toLowerCase(Locale.ROOT),names,
      nonEmpty(secret.ids(),-1L),nonEmpty(secret.modules(),"\u0000"),nonEmpty(secret.names(),"\u0000"));
    if(rows.size()>MAX_FINDINGS)throw new Unavailable("Too many recorded secret findings to check");
    for(var row:rows)add(byPath,(String)row.get("path"),line,engine((String)row.get("module"),(String)row.get("name")));
   }
   repoScanFindings(repo,secret,byPath);
  }catch(Unavailable e){throw e;}catch(RuntimeException e){throw new Unavailable("Recorded secret findings are unavailable");}
  return new Lines(byPath).engine(path,line)!=null;
 }
 /** Every recorded secret line of the repository: PR scan findings plus its recent repository-scan reports. */
 @Transactional(readOnly=true)
 public Lines lines(RepositoryEntity repo){
  var secret=secretRules();Map<String,Map<Integer,String>> byPath=new HashMap<>();
  try{
   prFindings(repo,secret,byPath);repoScanFindings(repo,secret,byPath);
  }catch(Unavailable e){throw e;}catch(RuntimeException e){throw new Unavailable("Recorded secret findings are unavailable");}
  return new Lines(byPath);
 }
 private void prFindings(RepositoryEntity repo,SecretRules secret,Map<String,Map<Integer,String>> byPath){
  // Webhooks store display names and the catalog stores slugs: match containers by slug key.
  String key=RepoCatalogDao.nameKey(repo.getRepoName());String label=repo.getApiLabel().toLowerCase(Locale.ROOT);
  var names=records.list(String.class,"SELECT DISTINCT c.repoName FROM PullRequestContainerEntity c WHERE LOWER(c.apiLabel)=?1",0,MAX_NAMES+1,label);
  if(names.size()>MAX_NAMES)throw new Unavailable("Too many pull request repositories to check for secrets");
  var matching=names.stream().filter(n->n!=null&&RepoCatalogDao.nameKey(n).equals(key)).toList();
  if(matching.isEmpty())return;
  // Sentinels keep each IN list non-empty; they match no rule.
  var rows=records.maps("SELECT v.fileName AS path,v.lineNum AS line,v.ruleIdentity.module AS module,v.violationName AS name FROM PullRequestViolationEntity v"
    +" WHERE LOWER(v.scan.container.apiLabel)=?1 AND v.scan.container.repoName IN ?2"
    +" AND (v.ruleIdentity.ruleId IN ?3 OR LOWER(v.ruleIdentity.module) IN ?4 OR v.violationName IN ?5)",0,MAX_FINDINGS+1,label,matching,
    nonEmpty(secret.ids(),-1L),nonEmpty(secret.modules(),"\u0000"),nonEmpty(secret.names(),"\u0000"));
  if(rows.size()>MAX_FINDINGS)throw new Unavailable("Too many recorded secret findings to check");
  for(var row:rows)add(byPath,(String)row.get("path"),row.get("line") instanceof Number n?n.intValue():0,engine((String)row.get("module"),(String)row.get("name")));
 }
 private void repoScanFindings(RepositoryEntity repo,SecretRules secret,Map<String,Map<Integer,String>> byPath){
  for(var scan:repoScans.findByRepositoryIdOrderBySubmitDateDesc(repo.getId(),PageRequest.of(0,RECENT_REPO_SCANS))){
   if(scan.getReportKey()==null)continue;
   RepoScanReport report=reports.getReport(scan).orElseThrow(()->new Unavailable("A repository scan report is unavailable"));
   for(var finding:report.findings()){
    var identity=finding.ruleIdentity();
    boolean isSecret=Boolean.TRUE.equals(finding.sensitive())||secret.contains(identity==null?null:identity.ruleId(),identity==null?null:identity.module(),finding.rule());
    if(isSecret)add(byPath,finding.file(),finding.line(),engine(identity==null?null:identity.module(),finding.rule()));
   }
  }
 }
 private static <T> List<T> nonEmpty(Set<T> values,T sentinel){return values.isEmpty()?List.of(sentinel):List.copyOf(values);}
 private static void add(Map<String,Map<Integer,String>> byPath,String path,int line,String engine){
  if(path==null||line<1)return;
  byPath.computeIfAbsent(normalize(path),k->new HashMap<>()).putIfAbsent(line,engine);
 }
 private String engine(String module,String rule){
  if(module!=null&&!module.isBlank())return module;
  try{var entity=rule==null?null:rules.getRule(rule);var dto=entity==null?null:entity.toDto();return dto==null?"a secrets rule":dto.getModule();}
  catch(RuntimeException e){return "a secrets rule";}
 }
 /** Separators unified and "." or empty segments dropped, so equivalent spellings compare equal. */
 static String normalize(String path){
  return Arrays.stream(path.replace('\\','/').split("/")).filter(part->!part.isEmpty()&&!part.equals(".")).collect(java.util.stream.Collectors.joining("/"));
 }
}

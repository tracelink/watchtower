package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** Resolves a finding to its rule, repository, pinned commit, path and line, or says why it cannot be assessed. */
@Component
public class FindingLocator {
 /** Where the finding is; {@code unavailable} is a plain reason when evidence cannot be gathered. */
 public record Located(String scanType,long scanId,String findingKey,String occurrenceKey,Long ruleId,String revision,
   RepositoryEntity repository,String commit,String path,int line,boolean sensitive,String unavailable) {
  Located withUnavailable(String reason){return new Located(scanType,scanId,findingKey,occurrenceKey,ruleId,revision,repository,commit,path,line,sensitive,reason);}
  Located withCommit(String full){return new Located(scanType,scanId,findingKey,occurrenceKey,ruleId,revision,repository,full,path,line,sensitive,unavailable);}
 }
 /** The located finding plus what the rule and the scan said about it; the message is scanner text and untrusted. */
 public record Detail(Located located,String ruleName,String module,String severity,String message,String scmRepoName) {
  static Detail of(Located located){return new Detail(located,null,null,null,null,null);}
 }
 static final int MAX_REPOSITORIES=50000;
 private final LedgerRepository records;private final RepoScanRepository repoScans;private final RepoScanReportService reports;private final RepositoryRepository repositories;
 public FindingLocator(LedgerRepository records,RepoScanRepository repoScans,RepoScanReportService reports,RepositoryRepository repositories){
  this.records=records;this.repoScans=repoScans;this.reports=reports;this.repositories=repositories;
 }
 @Transactional(readOnly=true)
 public Located locate(String scanType,long scanId,String findingKey){
  if(scanId<=0||findingKey==null||findingKey.isBlank()||findingKey.length()>64)throw new IllegalArgumentException("Invalid finding reference");
  return locateDetailed(scanType,scanId,findingKey).located();
 }
 /** The same lookup with the rule name, module, severity and message, for page context and read tools. */
 @Transactional(readOnly=true)
 public Detail locateDetailed(String scanType,long scanId,String findingKey){
  if(scanId<=0||findingKey==null||findingKey.isBlank()||findingKey.length()>64)throw new IllegalArgumentException("Invalid finding reference");
  String occurrence=FindingFeedbackService.occurrenceKey(scanType,scanId,findingKey);
  return switch(scanType==null?"":scanType){
   case "repository"->repositoryFinding(scanId,findingKey,occurrence);
   case "pull_request"->pullRequestFinding(scanId,findingKey,occurrence);
   case "upload"->Detail.of(new Located(scanType,scanId,findingKey,occurrence,null,null,null,null,null,0,false,"Uploaded code is not kept after the scan, so there is no source to assess."));
   default->throw new IllegalArgumentException("Unsupported scan type");
  };
 }
 private Detail repositoryFinding(long scanId,String key,String occurrence){
  var scan=repoScans.findById(scanId).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown scan"));
  var report=reports.getReport(scan).orElse(null);
  if(report==null)return Detail.of(new Located("repository",scanId,key,occurrence,null,null,null,null,null,0,false,"The scan report has expired, so the finding's location is unknown."));
  var f=report.findings().stream().filter(x->key.equals(x.findingKey())).findFirst().orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown finding"));
  var identity=f.ruleIdentity();
  var located=new Located("repository",scanId,key,occurrence,identity==null?null:identity.ruleId(),identity==null?null:identity.revision(),
    scanRepository(scan.getRepository()),scan.getCommitHash(),f.file(),f.line(),Boolean.TRUE.equals(f.sensitive()),null);
  return new Detail(complete(located),f.rule(),identity==null?null:identity.module(),f.severity(),f.message(),report.repository());
 }
 /**
  * The scan's repository as a loaded catalog row. The scan holds a lazy reference, and the
  * transaction ends before the source tools read it, which failed the assessment of every
  * repository finding with a server error.
  */
 private RepositoryEntity scanRepository(RepositoryEntity reference){
  if(reference==null)return null;
  return repository(reference.getApiLabel(),reference.getRepoName());
 }
 private Detail pullRequestFinding(long scanId,String key,String occurrence){
  long id;try{id=Long.parseLong(key);}catch(NumberFormatException e){throw new IllegalArgumentException("Invalid finding id");}
  var v=records.find(PullRequestViolationEntity.class,id);
  if(v==null||v.getScan().getId()!=scanId)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown finding");
  var container=v.getScan().getContainer();
  var located=new Located("pull_request",scanId,key,occurrence,v.getExecutionRuleId(),v.getRuleRevision(),
    repository(container.getApiLabel(),container.getRepoName()),v.getScan().getCommitHash(),v.getFileName(),v.getLineNum(),false,null);
  var identity=v.getRuleIdentity();
  return new Detail(complete(located),v.getViolationName(),identity==null?null:identity.module(),v.getSeverity()==null?null:v.getSeverity().name(),v.getMessage(),container.getRepoName());
 }
 private static Located complete(Located l){
  if(l.ruleId()==null)return l.withUnavailable("This finding has no recorded rule identity.");
  if(l.repository()==null)return l.withUnavailable("The repository is not in Watchtower's catalog, so its source cannot be read.");
  // Bitbucket abbreviates the hashes of a pull request; the evidence step completes them before reading source
  if(l.commit()==null||!l.commit().matches("[a-f0-9]{7,40}"))return l.withUnavailable("The scanned commit was not recorded for this finding.");
  if(l.path()==null||l.path().isBlank()||l.line()<1)return l.withUnavailable("The finding has no file and line.");
  return l;
 }
 /** The catalog repository a scan's source control name and integration label point at, or null when it is not in the catalog. */
 public RepositoryEntity catalogRepository(String apiLabel,String repoName){return repository(apiLabel,repoName);}
 /** Webhooks store display names and the catalog stores slugs: match by slug key, label ignoring case. */
 private RepositoryEntity repository(String apiLabel,String repoName){
  if(apiLabel==null||repoName==null)return null;
  var exact=repositories.findByApiLabelAndRepoName(apiLabel,repoName);if(exact!=null)return exact;
  String key=RepoCatalogDao.nameKey(repoName);
  return records.list(RepositoryEntity.class,"SELECT r FROM RepositoryEntity r WHERE LOWER(r.apiLabel)=?1",0,MAX_REPOSITORIES,apiLabel.toLowerCase(Locale.ROOT))
    .stream().filter(r->r.getRepoName()!=null&&RepoCatalogDao.nameKey(r.getRepoName()).equals(key)).findFirst().orElse(null);
 }
}

package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;

/** Explicit synthetic tests use the ordinary AWS durable execution/queue, never SCM source. */
@Service
public class AwsSecuritySetupService {
 @org.springframework.beans.factory.annotation.Autowired private AwsSecurityEvidencePolicy evidencePolicy;
 private final AwsSecuritySetupAccess access;private final AwsSecurityRunRepository runs;
 private final AwsSecurityPersistence persistence;private final AwsSecuritySettings settings;
 private final AwsSecurityImporter importer;private final AwsSecurityReadiness readiness;
 public AwsSecuritySetupService(AwsSecuritySetupAccess access,AwsSecurityRunRepository runs,AwsSecurityPersistence persistence,
   AwsSecuritySettings settings,AwsSecurityImporter importer,AwsSecurityReadiness readiness){
  this.access=access;this.runs=runs;this.persistence=persistence;this.settings=settings;this.importer=importer;this.readiness=readiness;
 }
 public record Request(String requestId,AwsSecuritySetupMode mode){}
 public record Receipt(String id,long version,String mode,String requester,long createdAt,String state,String reason,
   boolean finished,boolean configurationCurrent,boolean inputsVerified,boolean cleanupComplete,boolean reviewRetired,String reviewId,String jobId,
   String providerStatus,int findings,int missing,int pages,String sourceSha,long sourceBytes,String diffSha,
   Map<String,Integer> severities,List<com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProgressStep> progress,String reviewUrl,boolean canDeleteReview,long finishedAt){}
 public Receipt start(String actor,Request request){
  access.require(actor);
  if(request==null||request.mode()==null||request.requestId()==null||!request.requestId().matches("[a-fA-F0-9-]{36}"))
   throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Select a setup test and provide its request ID");
  // A timeout retry returns the original identity even if activation/configuration has since changed.
  String key=RuleRevision.definition("aws-setup-request","v1").field("actor",actor).field("request",request.requestId()).hash();
  var old=runs.findByExecutionKey(key);
  if(old.isPresent()){
   if(old.get().setupMode!=request.mode())throw new ResponseStatusException(HttpStatus.CONFLICT,"Request already selected a different test");
   return receipt(old.get());
  }
  if(settings.configurationIssue()!=null)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,settings.configurationIssue());
  if(!importer.sharedArtifacts())throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Shared S3 report storage is required for setup results");
  var checked=readiness.check();if(!checked.ready())throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,checked.reason());
  String revision=RuleRevision.definition("synthetic-setup","v1").field("mode",request.mode().name()).hash();
  var context=new ScanExecutionContext(request.requestId(),CodeScanType.REPOSITORY,0,0,"synthetic","packaged-setup-fixture","synthetic",revision,null,null,null,null);
  var snapshot=new AwsSecuritySnapshot(context,settings.profile(),new RuleExecutionIdentity(null,AwsSecurityModule.NAME,revision,"synthetic-setup-v1",null),"Synthetic setup test",RulePriority.HIGH,revision);
  access.require(actor);
  return receipt(persistence.enlistSetup(snapshot,settings.reviewSeconds(),actor,request.requestId(),request.mode()));
 }
 @org.springframework.transaction.annotation.Transactional(readOnly=true)
 public List<Receipt> history(String actor){access.require(actor);return runs.findByParentTypeOrderByCreatedAtDesc("setup",PageRequest.of(0,20)).stream().map(this::receipt).toList();}
 @org.springframework.transaction.annotation.Transactional(readOnly=true)
 public Receipt get(String actor,String id){access.require(actor);return receipt(setupRun(id));}
 @org.springframework.transaction.annotation.Transactional
 public Receipt stop(String actor,String id){access.require(actor);setupRun(id);persistence.requestStop(id);return receipt(setupRun(id));}
 @org.springframework.transaction.annotation.Transactional
 public Receipt recover(String actor,String id){access.require(actor);var run=setupRun(id);if(run.stage==AwsSecurityRun.Stage.FAILED&&run.providerTerminal&&run.artifactKey==null&&!run.providerDeleted)persistence.retryImport(id);else persistence.scheduleRecovery(id);return receipt(setupRun(id));}
 @org.springframework.transaction.annotation.Transactional(readOnly=true)
 public Object evidence(String actor,String id,int page)throws java.io.IOException{
  access.require(actor);var run=setupRun(id);
  if(page<0||page>=Math.max(1,run.artifactPages))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid evidence page");
  if(run.artifactKey==null)return Map.of("receipt",receipt(run),"findings",List.of());
  var manifest=importer.manifest(run.artifactKey);
  if(!run.id.equals(manifest.runId())||!AwsSecuritySnapshot.decode(run.snapshotJson).equals(manifest.snapshot()))throw new IllegalStateException("Setup evidence association mismatch");
  return Map.of("receipt",receipt(run),"manifest",manifest,"findings",page<manifest.pages().size()?importer.page(manifest,page):List.of());
 }
 private AwsSecurityRun setupRun(String id){var run=runs.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));if(!"setup".equals(run.parentType))throw new ResponseStatusException(HttpStatus.NOT_FOUND);return run;}
 private Receipt receipt(AwsSecurityRun r){
  var ref=r.reference().status();boolean current=settings.profile().revision().equals(AwsSecuritySnapshot.decode(r.snapshotJson).profile().revision());
  return new Receipt(r.id,r.version,r.setupMode==null?"Unknown":r.setupMode.name(),r.setupRequester,r.createdAt,
   r.needsReconciliation?"NEEDS_RECONCILIATION":r.stage.name(),r.statusReason,r.finished(),current,r.inputsVerified,r.cleanupComplete,r.providerDeleted,
   r.reviewId,r.jobId,r.providerStatus,r.importedCount,r.missingCount,r.artifactPages,r.sourceSha,r.sourceBytes,r.diffSha,Map.copyOf(r.nativeSeverityCounts),ref.progress(),r.providerDeleted||evidencePolicy==null?null:evidencePolicy.reviewUrl(r),ref.canDeleteProviderReview(),r.finished()?r.terminalAt:0);
 }
}

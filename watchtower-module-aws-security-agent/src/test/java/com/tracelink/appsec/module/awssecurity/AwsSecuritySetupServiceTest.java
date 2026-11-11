package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;

class AwsSecuritySetupServiceTest {
 AwsSecuritySetupAccess access;AwsSecurityRunRepository runs;AwsSecurityPersistence persistence;AwsSecurityImporter importer;AwsSecurityReadiness readiness;AwsSecuritySetupService service;
 @BeforeEach void setup(){
  access=mock(AwsSecuritySetupAccess.class);runs=mock(AwsSecurityRunRepository.class);persistence=mock(AwsSecurityPersistence.class);importer=mock(AwsSecurityImporter.class);readiness=mock(AwsSecurityReadiness.class);
  when(importer.sharedArtifacts()).thenReturn(true);when(readiness.check()).thenReturn(new AwsSecurityReadiness.Result(true,1,"Resources ready"));
  service=new AwsSecuritySetupService(access,runs,persistence,AwsTestSupport.settings(),importer,readiness);
 }
 @Test void revokedAccessStopsBeforeResourcesOrSubmission(){
  doThrow(new AccessDeniedException("revoked")).when(access).require("revoked");
  assertThrows(AccessDeniedException.class,()->service.start("revoked",new AwsSecuritySetupService.Request(UUID.randomUUID().toString(),AwsSecuritySetupMode.FULL)));
  verifyNoInteractions(runs,persistence,readiness,importer);
 }
 @Test void retryReturnsExactOldIdentityWithoutNewReadinessOrCloudWork(){
  var old=AwsTestSupport.run();old.parentType="setup";old.setupRequester="engineer";old.setupMode=AwsSecuritySetupMode.FULL;
  when(runs.findByExecutionKey(anyString())).thenReturn(Optional.of(old));
  var result=service.start("engineer",new AwsSecuritySetupService.Request(UUID.randomUUID().toString(),AwsSecuritySetupMode.FULL));
  assertEquals(old.id,result.id());verifyNoInteractions(persistence,readiness,importer);
  assertThrows(ResponseStatusException.class,()->service.start("engineer",new AwsSecuritySetupService.Request(UUID.randomUUID().toString(),AwsSecuritySetupMode.CLEAN)));
 }
 @Test void noBrowserSuppliedModeOrMalformedRequestCanReachEnlistment(){
  assertThrows(ResponseStatusException.class,()->service.start("engineer",new AwsSecuritySetupService.Request("not-an-id",AwsSecuritySetupMode.FULL)));
  assertThrows(ResponseStatusException.class,()->service.start("engineer",new AwsSecuritySetupService.Request(UUID.randomUUID().toString(),null)));
  verifyNoInteractions(persistence,readiness);
 }
 @Test void ordinaryAssessmentIdsCannotBeOperatedThroughSetup(){
  var normal=AwsTestSupport.run();when(runs.findById(normal.id)).thenReturn(Optional.of(normal));
  assertThrows(ResponseStatusException.class,()->service.stop("engineer",normal.id));verifyNoInteractions(persistence);
 }
 @Test void failedUnpublishedImportRetriesTheExistingJob(){
  var run=AwsTestSupport.run();run.parentType="setup";run.setupMode=AwsSecuritySetupMode.FULL;run.stage=AwsSecurityRun.Stage.FAILED;
  when(runs.findById(run.id)).thenReturn(Optional.of(run));service.recover("engineer",run.id);
  verify(persistence).retryImport(run.id);verify(persistence,never()).enlistSetup(any(),anyLong(),anyString(),anyString(),any());
 }
 @Test void evidenceMustMatchTheExactFrozenSetupScope()throws Exception{
  var run=AwsTestSupport.run();run.parentType="setup";run.setupMode=AwsSecuritySetupMode.FULL;run.artifactKey="retained";run.artifactPages=1;
  when(runs.findById(run.id)).thenReturn(Optional.of(run));
  var wrong=new AwsSecurityArtifact(1,run.id,AwsTestSupport.snapshot("different",com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.REPOSITORY),"COMPLETED","COMPLETE",1,0,0,List.of(),List.of(),null,List.of(),null,Map.of(),Map.of());
  when(importer.manifest("retained")).thenReturn(wrong);
  assertThrows(IllegalStateException.class,()->service.evidence("engineer",run.id,0));
  verify(importer,never()).page(any(),anyInt());
 }
}

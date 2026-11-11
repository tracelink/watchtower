package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.io.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.s3.model.Tag;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

class AssistantStorageTest {
 @TempDir Path root;
 String key="assistant/conversations/"+UUID.randomUUID()+"/"+UUID.randomUUID()+"/"+UUID.randomUUID()+".json.gz";
 @Test void localArtifactsAreImmutableBoundedAndPathChecked()throws Exception{
  var store=new LocalAssistantTranscriptStore(root);store.put(key,new byte[]{1,2,3});assertArrayEquals(new byte[]{1,2,3},store.get(key,3));assertThrows(IOException.class,()->store.get(key,2));assertThrows(IOException.class,()->store.put(key,new byte[]{4}));assertThrows(IllegalArgumentException.class,()->store.get("../../private",100));assertTrue(store.expire(key));assertThrows(IOException.class,()->store.get(key,100));assertFalse(store.shared());
 }
 @Test void linkedDirectoriesAreRejected()throws Exception{
  var store=new LocalAssistantTranscriptStore(root);Files.createSymbolicLink(root.resolve("assistant"),root);assertThrows(IOException.class,()->store.put(key,new byte[]{1}));
 }
 @Test void compressionAndRedactionLimitsAreEnforced()throws Exception{
  var state=new AssistantState();state.user(AssistantText.redact("password=do-not-store"));assertFalse(AssistantState.decode(state.encode(4096),4096).protocol.toString().contains("do-not-store"));assertThrows(IOException.class,()->state.encode(10));assertThrows(IOException.class,()->AssistantState.decode(state.encode(4096),10));assertEquals("[REDACTED]",AssistantText.redact("sk-abcdefghijklmnop"));assertThrows(IllegalArgumentException.class,()->AssistantText.bounded("xxxx",3));
 }
 @Test void s3WritesRemainEncryptedAndShared()throws Exception{
  var client=mock(S3Client.class);var store=new S3AssistantTranscriptStore(new S3Service("test-bucket",client));
  store.put(key,new byte[]{1});verify(client).putObject(argThat((PutObjectRequest r)->r.serverSideEncryption()==ServerSideEncryption.AES256),any(software.amazon.awssdk.core.sync.RequestBody.class));assertTrue(store.shared());
 }
 @Test void s3ExpiryTruncationIsPendingAndStorageFailuresAreReported()throws Exception{
  var client=mock(S3Client.class);var s3=new S3Service("test-bucket",client);
  when(client.listObjectVersions(any(ListObjectVersionsRequest.class))).thenReturn(ListObjectVersionsResponse.builder().isTruncated(true).build());assertFalse(s3.expireAssistantVersions(key));
  when(client.listObjectVersions(any(ListObjectVersionsRequest.class))).thenThrow(S3Exception.builder().message("failure").build());assertThrows(IOException.class,()->s3.expireAssistantVersions(key));
 }
 @Test void scheduledS3ExpiryTagsEveryExactVersionPreservesOtherTagsAndNeverDeletes()throws Exception {
  var client=mock(S3Client.class);var store=new S3AssistantTranscriptStore(new S3Service("test-bucket",client));
  when(client.listObjectVersions(any(ListObjectVersionsRequest.class))).thenReturn(ListObjectVersionsResponse.builder()
    .versions(ObjectVersion.builder().key(key).versionId("current").build(),ObjectVersion.builder().key(key).versionId("old").build(),ObjectVersion.builder().key(key+"-unrelated").versionId("neighbor").build())
    .deleteMarkers(DeleteMarkerEntry.builder().key(key).versionId("marker").build()).isTruncated(false).build());
  when(client.getObjectTagging(any(GetObjectTaggingRequest.class))).thenReturn(GetObjectTaggingResponse.builder().tagSet(Tag.builder().key("cost-center").value("existing").build()).build());
  assertFalse(store.expire(key));
  var tags=org.mockito.ArgumentCaptor.forClass(PutObjectTaggingRequest.class);verify(client,times(2)).putObjectTagging(tags.capture());
  assertEquals(Set.of("current","old"),tags.getAllValues().stream().map(PutObjectTaggingRequest::versionId).collect(java.util.stream.Collectors.toSet()));
  for(var request:tags.getAllValues()){
   assertEquals(key,request.key());assertEquals(2,request.tagging().tagSet().size());
   assertTrue(request.tagging().tagSet().stream().anyMatch(t->t.key().equals("watchtower-retention")&&t.value().equals("expired")));
  }
  verify(client,never()).deleteObject(any(DeleteObjectRequest.class));
 }
 @Test void lifecycleConfirmationWaitsForVersionsAndMarkersAndRepeatedTagsAreIdempotent()throws Exception {
  var client=mock(S3Client.class);var store=new S3AssistantTranscriptStore(new S3Service("test-bucket",client));
  when(client.listObjectVersions(any(ListObjectVersionsRequest.class))).thenReturn(
   ListObjectVersionsResponse.builder().versions(ObjectVersion.builder().key(key).versionId("version").build()).build(),
   ListObjectVersionsResponse.builder().deleteMarkers(DeleteMarkerEntry.builder().key(key).versionId("marker").build()).build(),
   ListObjectVersionsResponse.builder().isTruncated(true).build(),ListObjectVersionsResponse.builder().build());
  when(client.getObjectTagging(any(GetObjectTaggingRequest.class))).thenReturn(GetObjectTaggingResponse.builder().tagSet(Tag.builder().key("watchtower-retention").value("expired").build()).build());
  assertFalse(store.expire(key));assertFalse(store.expire(key));assertFalse(store.expire(key));assertTrue(store.expire(key));
  verify(client,never()).putObjectTagging(any(PutObjectTaggingRequest.class));verify(client,never()).deleteObject(any(DeleteObjectRequest.class));
 }
 @Test void taggingFailureNeverClaimsDeletionAndRetainsSafeDiagnostics()throws Exception {
  var client=mock(S3Client.class);var store=new S3AssistantTranscriptStore(new S3Service("test-bucket",client));
  when(client.listObjectVersions(any(ListObjectVersionsRequest.class))).thenReturn(ListObjectVersionsResponse.builder().versions(ObjectVersion.builder().key(key).versionId("version").build()).build());
  var denied=S3Exception.builder().statusCode(403).message("private response").build();
  when(client.getObjectTagging(any(GetObjectTaggingRequest.class))).thenThrow(denied);
  assertSame(denied,assertThrows(IOException.class,()->store.expire(key)).getCause());
  verify(client,never()).deleteObject(any(DeleteObjectRequest.class));
 }
}

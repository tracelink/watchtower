package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;
public class S3AssistantTranscriptStore implements AssistantTranscriptStore {
 private final S3Service s3;
 public S3AssistantTranscriptStore(S3Service s3){this.s3=s3;}
 public void put(String k,byte[] b)throws IOException{s3.putAssistantBytes(AssistantTranscriptStore.checkKey(k),b);}
 public byte[] get(String k,int max)throws IOException{return s3.getBoundedBytes(AssistantTranscriptStore.checkKey(k),max);}
 public boolean expire(String k)throws IOException{return s3.expireAssistantVersions(AssistantTranscriptStore.checkKey(k));}
 public boolean shared(){return true;}
}

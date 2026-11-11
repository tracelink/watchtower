package com.tracelink.appsec.watchtower.core.assistant;

import java.io.*;
import java.nio.file.*;

public class LocalAssistantTranscriptStore implements AssistantTranscriptStore {
 private final Path root;
 public LocalAssistantTranscriptStore(Path directory) throws IOException {Files.createDirectories(directory);root=directory.toRealPath();}
 private Path path(String key) throws IOException {
  Path target=root.resolve(AssistantTranscriptStore.checkKey(key));Path parent=root;
  for(Path part:root.relativize(target.getParent())){parent=parent.resolve(part);if(Files.isSymbolicLink(parent))throw new IOException("Linked transcript directory");}
  if(Files.isSymbolicLink(target))throw new IOException("Linked transcript file");return target;
 }
 public void put(String key,byte[] bytes)throws IOException {Path p=path(key);Files.createDirectories(p.getParent());Files.write(p,bytes,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);}
 public byte[] get(String key,int max)throws IOException {Path p=path(key);if(Files.size(p)>max)throw new IOException("Transcript exceeds limit");try(InputStream in=Files.newInputStream(p,LinkOption.NOFOLLOW_LINKS)){byte[] b=in.readNBytes(max+1);if(b.length>max)throw new IOException("Transcript exceeds limit");return b;}}
 public boolean expire(String key)throws IOException {Files.deleteIfExists(path(key));return true;}
 public boolean shared(){return false;}
}

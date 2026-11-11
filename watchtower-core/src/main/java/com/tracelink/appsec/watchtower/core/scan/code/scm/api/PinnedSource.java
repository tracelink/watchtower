package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;

/**
 * One pinned commit in a private temporary directory: downloaded within limits, checked for links
 * and size, handed to an operation, and always deleted. Shared by the assistant source tools and
 * variant search so both keep the same defenses. Interrupted downloads are removed by {@link #sweep}.
 */
public final class PinnedSource {
 @FunctionalInterface public interface Operation<T> { T apply(Path root) throws IOException; }
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(PinnedSource.class);
 private PinnedSource() { }
 public static <T> T open(IScmApi api,String repoName,String commit,Path parent,String prefix,SourceDownloadLimits limits,Operation<T> operation)throws IOException {
  Path temporary=null;
  try {
   Files.createDirectories(parent);
   if(Files.isSymbolicLink(parent))throw new IOException("Invalid workspace root");
   temporary=Files.createTempDirectory(parent,prefix);
   // POSIX private permissions when available; Windows ACLs inherit the server's private temp root.
   if(Files.getFileStore(temporary).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(temporary,PosixFilePermissions.fromString("rwx------"));
   Path root=temporary.resolve("source");
   api.downloadSource(repoName,commit,root,limits);
   if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS))throw new IOException("Pinned source unavailable");
   long total=0;int entries=0;
   try(var tree=Files.walk(root)) {
    for(Path path:tree.toList()) {
     if(Files.isSymbolicLink(path)||++entries>limits.entries())throw new IOException("Unsupported source tree");
     if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))total+=Files.size(path);
     if(total>limits.extractedBytes())throw new IOException("Source limit");
    }
   }
   return operation.apply(root);
  }finally{
   // A failed cleanup never replaces the operation's result or error; the scheduled sweep retries it.
   if(temporary!=null)try{delete(temporary);}catch(IOException e){LOG.warn("Temporary pinned source cleanup failed; the scheduled sweep will retry");}
  }
 }
 /** Removes this pod's leftovers older than the time-to-live; called from scheduled maintenance. */
 public static void sweep(Path parent,String prefix,long ttlMillis)throws IOException {
  if(!Files.isDirectory(parent,LinkOption.NOFOLLOW_LINKS))return;
  try(var paths=Files.list(parent)) {
   for(Path p:paths.filter(p->p.getFileName().toString().startsWith(prefix)).toList())
    if(Files.getLastModifiedTime(p,LinkOption.NOFOLLOW_LINKS).toMillis()<System.currentTimeMillis()-ttlMillis)delete(p);
  }
 }
 static void delete(Path root)throws IOException {
  try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
 }
}

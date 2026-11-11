package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.process.*;

/** User-approved direct execution, using the same engine adapters as normal scans.
 * This is a bounded subprocess, not a security sandbox. No application credentials are forwarded
 * in the environment; host filesystem and network isolation remain deferred.
 */
@Component
@ConditionalOnProperty(name="watchtower.rule-testing.direct-enabled",havingValue="true",matchIfMissing=true)
public class DirectRuleTestClient implements RuleTestClient {
 private static final String MAIN="com.tracelink.appsec.watchtower.web.RuleTestSuiteRunner";
 private final ProcessRunner runner;private final Path directory;private final boolean enabled;
 private volatile String profile;
 /** Whole-checkout searches get a longer deadline and output bound than single-fixture tests. */
 private final Duration searchDeadline;private static final int SEARCH_OUTPUT_BYTES=4*1024*1024;
 public DirectRuleTestClient(ProcessRunner runner,@Value("${watchtower.rule-testing.enabled:true}")boolean enabled,
   @Value("${watchtower.rule-testing.directory:${java.io.tmpdir}/watchtower-rule-testing}")String directory) {
  this.runner=runner;this.enabled=enabled;this.searchDeadline=Duration.ofSeconds(300);
  try{this.directory=Path.of(directory).toFile().getCanonicalFile().toPath();}
  catch(java.io.IOException e){throw new IllegalArgumentException("Temporary test directory unavailable");}
 }
 @Override public boolean available(){
  if(!enabled)return false;
  try {Class.forName(MAIN,false,getClass().getClassLoader());return true;}
  catch(ClassNotFoundException e){return false;}
 }
 @Override public String executionIdentity(){
  // Java artifacts are immutable for the lifetime of this application, as for normal scanners.
  // Fingerprint the whole packaged runtime (or development classpath), not just the entry point.
  if(profile!=null)return profile;
  synchronized(this){
   if(profile!=null)return profile;
   try {
    var digest=java.security.MessageDigest.getInstance("SHA-256");
    digest.update(("direct-v2/"+Runtime.version()+"/"+System.getProperty("java.vendor")).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    for(String entry:System.getProperty("java.class.path").split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
     Path artifact=Path.of(entry).toAbsolutePath().normalize();
     if(Files.isDirectory(artifact)) {
      try(var files=Files.walk(artifact)) {
       for(Path file:files.filter(Files::isRegularFile).sorted().toList()) {
        digest.update(artifact.relativize(file).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        fingerprint(digest,file);
       }
      }
     }else fingerprint(digest,artifact);
    }
    // Surefire's manifest jar has a minimal classpath; include the actual entry point as well.
    try(var in=getClass().getClassLoader().getResourceAsStream(MAIN.replace('.','/')+".class")) {
     if(in==null)return "unavailable";
     digest.update(in.readAllBytes());
    }
    profile=java.util.HexFormat.of().formatHex(digest.digest());return profile;
   }catch(Exception e){return "unavailable";}
  }
 }
 private static void fingerprint(java.security.MessageDigest digest,Path file)throws java.io.IOException {
  digest.update(java.nio.ByteBuffer.allocate(Long.BYTES).putLong(Files.size(file)).array());
  try(var in=Files.newInputStream(file)){byte[] buffer=new byte[65536];int count;while((count=in.read(buffer))!=-1)digest.update(buffer,0,count);}
 }
 @Override public RuleTestSuite.Result test(RuleTestSuite.Request request){
  return execute(RuleDefinitionHistory.encode(request),false,Duration.ofSeconds(110),1024*1024,RuleTestSuite.Result.class);
 }
 @Override public RuleTestSuite.SearchResult search(RuleTestSuite.SearchRequest request){
  return execute(RuleDefinitionHistory.encode(request),true,searchDeadline,SEARCH_OUTPUT_BYTES,RuleTestSuite.SearchResult.class);
 }
 private <T> T execute(String encoded,boolean search,Duration deadline,int outputBytes,Class<T> type){
  if(!available())throw new IllegalStateException("Direct tester unavailable");
  Path task=null;
  try {
   Files.createDirectories(directory);
   if(!directory.toRealPath().equals(directory))throw new IllegalArgumentException("Private local test storage required");
   Files.setPosixFilePermissions(directory,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
   task=Files.createTempDirectory(directory,"test-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
   Path input=task.resolve("request.json");Files.writeString(input,encoded);
   Files.setPosixFilePermissions(input,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
   // Share only the installed npm dependency directory. Each tester writes its own bridge files.
   Path installed=Path.of("eslint_work/node_modules").toAbsolutePath().normalize();
   if(Files.isDirectory(installed)) {
    Files.createDirectory(task.resolve("eslint_work"));Files.createSymbolicLink(task.resolve("eslint_work/node_modules"),installed);
   }
   var command=command(input,task,search?"-Xmx1024m":"-Xmx512m");if(search)command.add(1,"-Dwatchtower.rule-test.mode=search");
   String path=Objects.toString(System.getenv("PATH"),"/usr/local/bin:/usr/bin:/bin");
   var environment=new HashMap<>(Map.of("PATH",path,"HOME",task.toString(),"TMPDIR",task.toString(),"PYTHONDONTWRITEBYTECODE","1","AWS_EC2_METADATA_DISABLED","true"));
   String betterleaks=System.getenv("WATCHTOWER_BETTERLEAKS_PATH");
   if(betterleaks!=null&&!betterleaks.isBlank())environment.put("WATCHTOWER_BETTERLEAKS_PATH",Path.of(betterleaks).toAbsolutePath().normalize().toString());
   String opengrep=System.getenv("WATCHTOWER_OPENGREP_PATH");
   if(opengrep!=null&&!opengrep.isBlank())environment.put("WATCHTOWER_OPENGREP_PATH",Path.of(opengrep).toAbsolutePath().normalize().toString());
   var result=runner.run(new ProcessRequest(command,task,deadline,outputBytes,environment));
   if(!result.isSuccess()||result.stdoutTruncated()||result.stderrTruncated())
    throw new IllegalStateException("Direct engine test failed or exceeded its time/output limit");
   return RuleDefinitionHistory.JSON.readValue(result.stdout(),type);
  }catch(java.io.IOException e){throw new IllegalStateException("Direct engine input or output unavailable");}
  finally{if(task!=null)delete(task);}
 }
 static List<String> command(Path input,Path task){return command(input,task,"-Xmx512m");}
 static List<String> command(Path input,Path task,String heap){
  var command=new ArrayList<>(List.of(Path.of(System.getProperty("java.home"),"bin/java").toString(),
    heap,"-XX:ActiveProcessorCount=1","-Djava.io.tmpdir="+task,"-Dwatchtower.rule-test.input="+input));
  String classpath=System.getProperty("java.class.path");
  var entries=classpath.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator));
  classpath=String.join(java.io.File.pathSeparator,Arrays.stream(entries).map(p->Path.of(p).toAbsolutePath().normalize().toString()).toList());
  command.addAll(List.of("-cp",classpath));
  // Packaged Spring Boot classes/dependencies are nested, so use its loader without starting Spring.
  if(entries.length==1&&bootJar(Path.of(entries[0]))) {
   command.add(1,"-Dloader.main="+MAIN);command.add("org.springframework.boot.loader.launch.PropertiesLauncher");
  }else command.add(MAIN);
  return command;
 }
 private static boolean bootJar(Path path){
  if(!path.toString().endsWith(".jar"))return false;
  try(var jar=new java.util.jar.JarFile(path.toFile())){return jar.getEntry("org/springframework/boot/loader/launch/PropertiesLauncher.class")!=null;}
  catch(java.io.IOException e){return false;}
 }
 @Scheduled(fixedDelayString="${watchtower.rule-testing.cleanup-delay-ms:60000}")
 public void cleanup(){
  if(!Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(directory))return;
  try(var tasks=Files.list(directory)){
   for(var task:tasks.limit(1000).toList())if(task.getFileName().toString().matches("test-[A-Za-z0-9]+")
     &&Files.getLastModifiedTime(task,LinkOption.NOFOLLOW_LINKS).toMillis()<System.currentTimeMillis()-900000)delete(task);
  }catch(java.io.IOException e){throw new IllegalStateException("Temporary rule test cleanup unavailable");}
 }
 static void delete(Path task){
  try(var paths=Files.walk(task)) {for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
  catch(java.io.IOException e){throw new IllegalStateException("Temporary rule test cleanup failed");}
 }
}

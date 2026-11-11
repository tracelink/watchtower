package com.tracelink.appsec.module.opengrep.scanner;

import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import com.tracelink.appsec.module.opengrep.*;
import com.tracelink.appsec.module.opengrep.model.*;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.*;
import com.tracelink.appsec.watchtower.core.process.*;

/** Pinned standalone release, local configs and bounded direct execution; no sandbox. */
public class OpengrepScanner implements ICodeScanner, AutoCloseable {
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(OpengrepScanner.class);
 public static final String BINARY_ENV="WATCHTOWER_OPENGREP_PATH";
 public static final Map<String,String> RELEASE_HASHES=Map.of(
  "linux-amd64","a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7",
  "linux-arm64","90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8",
  "mac-amd64","fcf47da30d5c3a11119f2ec4e0d1ee55e3c3822e8f90d909bf9f33dfce99044a",
  "mac-arm64","f1aaa30b88959cb82522c4e1475816278a1f161f994509a518453c0455f9d24b");
 private final ProcessRunner runner;
 private final Path binary;
 private final Path session;
 private String verifiedHash;
 public OpengrepScanner(){this(new ProcessRunner(),locate());}
 public OpengrepScanner(ProcessRunner runner,Path binary){this(runner,binary,null);}
 private OpengrepScanner(ProcessRunner runner,Path binary,Path session){this.runner=runner;this.binary=binary;this.session=session;}
 /** One private cache for a reviewed subprocess suite; never shared between requests. */
 public static OpengrepScanner reviewedSession()throws IOException {
  Path session=Files.createTempDirectory("watchtower-reviewed-opengrep-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
  return new OpengrepScanner(new ProcessRunner(),locate(),session);
 }
 /** Extensions of the languages the adapter admits: Python, JavaScript, TypeScript, Java and YAML. */
 public List<String> getDefaultFileTypes(){return List.of(".py",".pyi",".js",".jsx",".mjs",".cjs",".ts",".tsx",".mts",".cts",".java",".yaml",".yml");}
 public List<Class<? extends RuleDto>> getSupportedRuleClass(){return List.of(OpengrepCustomRuleDto.class,OpengrepProvidedRuleDto.class);}
 private static Path locate(){
  String override=System.getenv(BINARY_ENV);
  if(override!=null&&!override.isBlank())return Path.of(override).toAbsolutePath().normalize();
  for(String directory:Objects.toString(System.getenv("PATH"),"").split(java.io.File.pathSeparator)){
   if(directory.isBlank())continue;var path=Path.of(directory).resolve("opengrep");if(Files.isExecutable(path))return path.toAbsolutePath().normalize();
  }
  return Path.of("/usr/local/bin/opengrep");
 }
 public boolean pinnedBinaryAvailable(){try{binaryHash();return true;}catch(Exception e){return false;}}
 private String binaryHash()throws Exception {
  if(!Files.isRegularFile(binary)||!Files.isExecutable(binary)||Files.size(binary)>100*1024*1024)throw new IOException("Pinned binary unavailable");
  var digest=java.security.MessageDigest.getInstance("SHA-256");
  try(var in=Files.newInputStream(binary)){byte[] data=new byte[65536];int n;while((n=in.read(data))!=-1)digest.update(data,0,n);}
  String hash=HexFormat.of().formatHex(digest.digest());
  if(!RELEASE_HASHES.containsValue(hash))throw new IOException("Binary checksum differs from the pinned release");return hash;
 }
 private static Map<String,String> environment(Path home,Path task){return Map.of(
  "PATH","/usr/local/bin:/usr/bin:/bin","HOME",home.toString(),"TMPDIR",task.toString(),
  "SEMGREP_SEND_METRICS","off","SEMGREP_ENABLE_VERSION_CHECK","0","PYTHONDONTWRITEBYTECODE","1");}
 private ProcessResult run(List<String> args,Path cwd,Path task,Duration timeout)throws IOException {
  var command=new ArrayList<String>();command.add(binary.toString());command.addAll(args);
  return runner.run(new ProcessRequest(command,cwd,timeout,8*1024*1024,environment(session==null?task:session,task)));
 }
 /** The engine's report and how many target files it could not analyze. */
 record Analysis(com.fasterxml.jackson.databind.JsonNode output,int unanalyzedFiles){}
 /**
  * Reads what the engine produced. A file it could not analyze (bad syntax, a time limit on that file) is counted and the rest of
  * the report kept: one unparseable file, such as a templated YAML, must not hide every other finding. Anything that
  * is not about a target file (rule or configuration errors, a timeout, truncated or missing output) refuses the whole
  * run, because then the findings cannot be trusted.
  */
 static Analysis analyze(ProcessResult result,Path root)throws IOException {
  if(result.timedOut()||result.stdoutTruncated()||result.stderrTruncated())complete(result);
  com.fasterxml.jackson.databind.JsonNode output;
  try{output=RuleDefinitionHistory.JSON.readTree(result.stdout());}catch(IOException unreadable){output=null;}
  if(output==null||!output.path("results").isArray()||!output.path("errors").isArray()||!output.path("paths").path("scanned").isArray()){
   complete(result);
   throw new IllegalArgumentException("Incomplete JSON report");
  }
  var files=new HashSet<String>();
  for(var error:output.path("errors")){
   String type=error.path("type").toString().toLowerCase(Locale.ROOT);
   String path=error.path("path").asText("");
   boolean ofATargetFile=!path.isBlank()&&!type.contains("rule")&&root.resolve(path).normalize().startsWith(root);
   if(!ofATargetFile)throw new IllegalArgumentException("Engine reported rule, parser or timeout errors");
   files.add(path);
  }
  // A failing exit with nothing to explain it is a failed run, not a clean one.
  if(!result.isSuccess()&&files.isEmpty())complete(result);
  return new Analysis(output,files.size());
 }
 private static void complete(ProcessResult result){
  if(!result.isSuccess()||result.stdoutTruncated()||result.stderrTruncated())
   // Numbers and flags only: the process' own text can hold rule, source and path data
   throw new IllegalStateException("Opengrep failed or exceeded its time/output limit (exit code "+result.exitCode()+(result.timedOut()?", timed out":"")+(result.stdoutTruncated()||result.stderrTruncated()?", output too large":"")+")");
 }
 public EngineExecutionIdentity getExecutionIdentity(CodeScanConfig config){
  try {
   var hash=RuleRevision.definition("opengrep-direct","v1").field("binary",binaryHash())
     .field("cache",session==null?"invocation":"reviewed-suite")
     .field("settings","json/local-config/strict/no-metrics/no-nosem/intrafile/jobs1/timeout10/memory512/target1MiB/no-git-ignore")
     .field("java",JavaEngineExecutionIdentity.capture("Opengrep",this,config,getClass(),OpengrepDefinition.class).fingerprint()).hash();
   // Standalone artifact is pinned; host/native dependencies have not been certified.
   return new EngineExecutionIdentity("Opengrep",OpengrepModule.VERSION,hash,false);
  }catch(Exception e){return EngineExecutionIdentity.unknown("Opengrep");}
 }
 public CodeScanReport scan(CodeScanConfig config){
  var report=new CodeScanReport();Path task=null;
  try {
   String before=binaryHash();Path root=config.getWorkingDirectory().toRealPath();
   task=Files.createTempDirectory("watchtower-opengrep-");
   Files.setPosixFilePermissions(task,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
   if(session==null||!before.equals(verifiedHash)){
    var version=run(List.of("--version"),task,task,Duration.ofSeconds(40));complete(version);
    if(!OpengrepModule.VERSION.equals(version.stdout().trim()))throw new IllegalArgumentException("Opengrep version mismatch");
    verifiedHash=before;
   }
   var selected=new HashMap<String,RuleDto>();var definitions=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();
   for(var dto:config.getRuleset().getAllRules())if(dto instanceof OpengrepRuleDto opengrep){
    if(selected.put(opengrep.getEngineRuleId(),dto)!=null)throw new IllegalArgumentException("Duplicate stable engine rule ID");
    definitions.add(OpengrepDefinition.parse(dto));
   }
   if(definitions.isEmpty())throw new IllegalArgumentException("No selected Opengrep rules");
   Path rules=task.resolve("rules.json");Files.writeString(rules,RuleDefinitionHistory.encode(Map.of("rules",definitions)));
   var args=new ArrayList<>(List.of("scan","--config",rules.toString(),"--json","--quiet","--strict","--disable-version-check",
     "--no-git-ignore","--no-rewrite-rule-ids","--disable-nosem","--taint-intrafile","--jobs=1","--timeout=10","--max-memory=512","--max-target-bytes=1048576",
     "--exclude","test","--exclude","node_modules",root.toString()));
   var result=run(args,root,task,Duration.ofSeconds(90));
   var analysis=analyze(result,root);var output=analysis.output();
   if(analysis.unanalyzedFiles()>0)
    report.addError(new CodeScanError("Opengrep could not analyze "+analysis.unanalyzedFiles()+" file"+(analysis.unanalyzedFiles()==1?"":"s")+" (syntax or time limit); its findings cover the rest"));
   if(output.path("paths").path("scanned").isEmpty()){
    if(!output.path("results").isEmpty())throw new IllegalArgumentException("Matches without scanned targets");
    report.setExecutionStatus("UNSUPPORTED");
   }
   if(output.path("results").size()>10000)throw new IllegalArgumentException("Match limit exceeded");
   for(var finding:output.path("results")){
    var dto=selected.get(finding.path("check_id").asText());
    if(dto==null)throw new IllegalArgumentException("Unknown engine rule ID");
    Path file=Path.of(finding.path("path").asText());if(!file.isAbsolute())file=root.resolve(file);file=file.toRealPath();
    int line=finding.path("start").path("line").asInt();
    if(!file.startsWith(root)||line<1)throw new IllegalArgumentException("Invalid finding location");
    var violation=new CodeScanViolation();violation.setFileName(file.toString());violation.setLineNum(line);violation.setViolationName(dto.getName());
    violation.setMessage(dto.getMessage());violation.setSeverity(dto.getPriority());violation.setRuleIdentity(dto.getExecutionIdentity());report.addViolation(violation);
   }
   if(!before.equals(binaryHash()))throw new IllegalArgumentException("Runtime changed during scan");
  }catch(Exception e){
   // Raw CLI output/rule/source/path data never reaches logs or the persisted error. Only this class's own fixed
   // messages are repeated, so the reason a scan failed is visible without exposing any of that.
   String reason=e.getClass()==IllegalArgumentException.class||e.getClass()==IllegalStateException.class?e.getMessage():e.getClass().getSimpleName();
   LOG.warn("Opengrep scan did not complete: {}",reason);
   report=new CodeScanReport();report.addError(new CodeScanError("Opengrep execution incomplete ("+reason+"): check pinned binary, rule syntax, language and execution limits"));
  }finally{
   if(task!=null)try{delete(task);}catch(IOException e){report=new CodeScanReport();report.addError(new CodeScanError("Opengrep temporary configuration cleanup failed"));}
  }
  return report;
 }
 private static void delete(Path root)throws IOException {
  try(var paths=Files.walk(root)){for(var file:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}
 }
 @Override public void close()throws IOException {if(session!=null&&Files.exists(session))delete(session);}
}

package com.tracelink.appsec.module.betterleaks.engine;

import java.nio.file.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.model.*;
import com.tracelink.appsec.module.betterleaks.scanner.BetterleaksScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.*;

/** Actual binary/version/configuration evidence, without certifying native or environment inputs. */
final class BetterleaksExecutionIdentity {
 private BetterleaksExecutionIdentity() { }
 static EngineExecutionIdentity capture(BetterleaksEngine engine, ICodeScanner scanner,
   CodeScanConfig config, List<BetterleaksAllowlistEntry> allowlist) {
  try {
   if(engine.getClass()!=BetterleaksEngine.class || scanner.getClass()!=BetterleaksScanner.class
     || config.getRuleset()==null) return EngineExecutionIdentity.unknown("betterleaks");
   var version=engine.captureVersion();
   if(!version.isSuccess() || version.stdoutTruncated() || version.stderrTruncated())
    return EngineExecutionIdentity.unknown("betterleaks");
   String number=version.stdout().strip();
   if(!number.matches("v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,64})?"))
    return EngineExecutionIdentity.unknown("betterleaks");
   String binaryHash=hashBinary(engine.binary());
   var selected=config.getRuleset().getAllRules().stream().filter(BetterleaksRuleDto.class::isInstance)
     .map(BetterleaksRuleDto.class::cast).toList();
   var disabled=allowlist.stream().filter(a->a.pathGlob()==null&&a.ruleId()!=null)
     .map(BetterleaksAllowlistEntry::ruleId).collect(Collectors.toSet());
   var enabled=selected.stream().filter(r->!disabled.contains(r.getBetterleaksId())).toList();
   String rendered=BetterleaksConfigRenderer.render(allowlist.stream().filter(a->a.pathGlob()!=null).toList(),
     enabled.stream().filter(BetterleaksCustomRuleDto.class::isInstance).map(BetterleaksCustomRuleDto.class::cast).toList());
   var java=JavaEngineExecutionIdentity.capture("betterleaks",scanner,config,
     BetterleaksScanner.class,BetterleaksEngine.class,BetterleaksConfigRenderer.class,BetterleaksReportParser.class);
   var command=engine.buildCommand(Path.of("config"),Path.of("ignore"),enabled.stream().map(BetterleaksRuleDto::getBetterleaksId).toList());
   String fingerprint=RuleRevision.definition("betterleaks","partial-execution-v1")
     .field("binary",binaryHash).field("config",rendered).field("java",java.configurationHash())
     .field("command",String.join("\n",command.subList(1,command.size())))
     .hash();
   return new EngineExecutionIdentity("betterleaks",number+"/java:"+java.version(),fingerprint,false);
  } catch(Exception | LinkageError exception) {return EngineExecutionIdentity.unknown("betterleaks");}
 }
 private static String hashBinary(String command)throws Exception{
  Path path=Path.of(command);
  if(path.getNameCount()==1&&!path.isAbsolute()){
   path=null;for(String folder:System.getenv().getOrDefault("PATH","").split(java.io.File.pathSeparator)){
    if(folder.isBlank())continue;Path candidate=Path.of(folder).resolve(command);
    if(Files.isRegularFile(candidate)&&Files.isExecutable(candidate)){path=candidate;break;}
   }
  }
  if(path==null)throw new IOException("Binary unavailable");path=path.toRealPath();
  long size=Files.size(path);if(size==0||size>256L*1024*1024)throw new IOException("Binary evidence limit");
  var digest=MessageDigest.getInstance("SHA-256");long total=0;
  try(var in=Files.newInputStream(path)){byte[] buffer=new byte[65536];for(int read;(read=in.read(buffer))!=-1;){total+=read;if(total>256L*1024*1024)throw new IOException("Binary evidence limit");digest.update(buffer,0,read);}}
  if(total!=size)throw new IOException("Binary changed");return HexFormat.of().formatHex(digest.digest());
 }
}

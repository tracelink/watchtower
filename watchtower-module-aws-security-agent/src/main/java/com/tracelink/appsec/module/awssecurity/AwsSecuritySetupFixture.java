package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.zip.ZipInputStream;
import org.springframework.core.io.ClassPathResource;

/** Immutable packaged synthetic content; this code never executes the Python fixture. */
final class AwsSecuritySetupFixture {
 static void write(Path directory,AwsSecuritySetupMode mode)throws IOException{
  try(var zip=new ZipInputStream(new ClassPathResource("awssecurity/canary/source.zip").getInputStream())){
   var entry=zip.getNextEntry();if(entry==null||!"app.py".equals(entry.getName()))throw new IOException("Synthetic fixture unavailable");
   String source=new String(zip.readNBytes(8193),StandardCharsets.UTF_8);
   if(source.length()>8192||zip.getNextEntry()!=null)throw new IOException("Synthetic fixture exceeds its bound");
   if(mode==AwsSecuritySetupMode.CLEAN){
    // The vulnerable fixture is checked here only to prove the packaged file is the expected one. The clean
    // variant shares none of it: no web route, no process, no request input, so a reviewer has nothing to flag.
    // (It used to keep an open /diagnostic route that returned system information, and AWS reported findings
    // on it on every run, so the clean check could never pass.)
    if(!source.contains("shell=True"))throw new IOException("Synthetic clean fixture mismatch");
    source="# Synthetic review fixture. Never deploy or execute this code.\n"
      +"def add(left: int, right: int) -> int:\n"
      +"    \"\"\"Return the sum of two integers.\"\"\"\n"
      +"    return left + right\n";
   }
   Files.writeString(directory.resolve("app.py"),source,StandardCharsets.UTF_8);
  }
 }
 static byte[] patch()throws IOException{try(var input=new ClassPathResource("awssecurity/canary/changes.diff").getInputStream()){return input.readAllBytes();}}
}

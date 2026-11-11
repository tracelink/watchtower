package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** Downloadable synthetic-only preparation. This never contacts AWS or changes activation. */
@RestController @PreAuthorize("hasAuthority('AWS Security Administration') and hasAuthority('Repository Settings View')")
public class AwsSecuritySetupController {
 private final AwsSecuritySetupService tests;
 public AwsSecuritySetupController(AwsSecuritySetupService tests){this.tests=tests;}
 @GetMapping("/aws-security/setup/tests")
 public Object history(org.springframework.security.core.Authentication actor){return tests.history(actor.getName());}
 @PostMapping("/aws-security/setup/tests")
 public Object start(@RequestBody AwsSecuritySetupService.Request request,org.springframework.security.core.Authentication actor){return tests.start(actor.getName(),request);}
 @GetMapping("/aws-security/setup/tests/{id}")
 public Object test(@PathVariable String id,org.springframework.security.core.Authentication actor){return tests.get(actor.getName(),id);}
 @GetMapping("/aws-security/setup/tests/{id}/receipt")
 public ResponseEntity<?> receipt(@PathVariable String id,@RequestParam(defaultValue="0")int page,org.springframework.security.core.Authentication actor)throws IOException{
  return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(tests.evidence(actor.getName(),id,page));
 }
 @PostMapping("/aws-security/setup/tests/{id}/stop")
 public Object stop(@PathVariable String id,org.springframework.security.core.Authentication actor){return tests.stop(actor.getName(),id);}
 @PostMapping("/aws-security/setup/tests/{id}/recover")
 public Object recover(@PathVariable String id,org.springframework.security.core.Authentication actor){return tests.recover(actor.getName(),id);}
 @GetMapping("/aws-security/setup/canary-kit")
 public ResponseEntity<byte[]> kit()throws IOException {
  var bytes=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(bytes)){
   for(String file:new String[]{"source.zip","changes.diff","receipt.json"})try(var input=new ClassPathResource("awssecurity/canary/"+file).getInputStream()){add(zip,file,input.readAllBytes());}
   add(zip,"README.md",README.getBytes(StandardCharsets.UTF_8));
  }
  return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/zip")).header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=watchtower-synthetic-canary.zip").header("X-Content-Type-Options","nosniff").body(bytes.toByteArray());
 }
 private static void add(ZipOutputStream zip,String name,byte[] bytes)throws IOException{var entry=new ZipEntry(name);entry.setTime(0);zip.putNextEntry(entry);zip.write(bytes);zip.closeEntry();}
 private static final String README="""
  # Watchtower AWS Security Agent synthetic setup kit

  This kit contains synthetic code with an intentional command-injection example. Never execute
  or deploy the fixture. No repository code, credentials, or personal data is included.
  Downloading this kit does not submit a review, enable the scanner, or grant repository code access.

  Deployment owner steps (see docs/aws-security-agent-operations.md in the Watchtower repository):
  1. Obtain approval for the synthetic-only source upload and provider reviews, with a spending
     limit. Leave the scanner off for ordinary repository scans and keep PR enforcement separate.
  2. Verify source.zip and changes.diff against receipt.json. Use a dedicated immutable canary
     input prefix in the configured bucket, retaining the deployment's encryption mode.
  3. Run one full, one differential, and one clean synthetic review serially. Persist each
     returned review/job ID before polling; do not blindly repeat an uncertain create/start.
  4. Verify service-role source readability, terminal states, retained evidence usefulness,
     recovery/queue behavior and input/provider deletion. Record observed failures as failures.
     Complete user-owned migration checks separately; downloading the kit does not pass them.
  5. Review and record the test results. Turn on AWS Security Agent in Scanner modules
     for ordinary scans. No deployment approval or scan enablement flag is required.
  6. Select the provided Security review rule in the repository effective ruleset, turn on
     the scanner in Scanner modules and start a scan. There is no extra repository AWS setup.
     AWS review records are kept until manually deleted; temporary source inputs are deleted
     after terminal proof. PR enforcement and terminal failure policy remain separate decisions.

  The authoritative runbook includes the exact SDK request shapes and full acceptance checks.
  This download is preparation only; it contains no automatic AWS execution or IAM changes.
  """;
}

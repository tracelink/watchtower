package com.tracelink.appsec.watchtower.core.metrics;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;

/** Administrative derived-data repair always requires a reviewed, current dry-run identity. */
@RestController
@RequestMapping("/admin/metrics/reconciliation")
@PreAuthorize("hasAuthority('Scan Admin')")
public class MetricsReconciliationController {
 private final MetricsProjectionWriter writer;
 public MetricsReconciliationController(MetricsProjectionWriter writer){this.writer=writer;}
 @GetMapping("/{type}") public MetricsProjectionWriter.Reconciliation preview(@PathVariable MetricsProjectionWriter.ReconcileType type){return writer.reconcile(type,null);}
 public record Repair(String dryRunFingerprint,boolean confirm) { }
 @PostMapping("/{type}") public MetricsProjectionWriter.Reconciliation repair(@PathVariable MetricsProjectionWriter.ReconcileType type,@RequestBody Repair request){
  if(!request.confirm()||request.dryRunFingerprint()==null||!request.dryRunFingerprint().matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Review and confirm a dry run first");
  return writer.reconcile(type,request.dryRunFingerprint());
 }
 @ExceptionHandler(IllegalStateException.class) ResponseEntity<?> conflict(IllegalStateException error){return ResponseEntity.status(409).body(Map.of("error",error.getMessage()));}
 @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> invalid(IllegalArgumentException error){return ResponseEntity.badRequest().body(Map.of("error",error.getMessage()));}
}

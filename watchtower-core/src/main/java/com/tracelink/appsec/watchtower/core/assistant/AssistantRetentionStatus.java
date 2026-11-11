package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;

/**
 * Whether the daily transcript retention failed recently, for the "Transcript cleanup failing"
 * chip. A run writes one RETENTION_FAILED row with "STORAGE_RETENTION:count:code"; older builds
 * wrote one bare "STORAGE_RETENTION" row per transcript, so those rows count one each.
 */
public final class AssistantRetentionStatus {
 /** The retention job runs daily; a failure older than this has been superseded by a later run. */
 static final long WINDOW_MILLIS=26L*60*60*1000;
 private AssistantRetentionStatus() { }
 static Map<String,Object> recent(AssistantPersistence db,long now){
  var rows=db.records().maps("SELECT row FROM AssistantAuditEntity row WHERE row.event='RETENTION_FAILED' AND row.createdAt>?1 ORDER BY row.auditId DESC",0,500,now-WINDOW_MILLIS);
  return summarize(rows);
 }
 static Map<String,Object> summarize(List<Map<String,Object>> rows){
  if(rows.isEmpty())return null;
  long failures=0;String code=null;
  for(var row:rows){
   String[] parts=Objects.toString(row.get("target"),"").split(":",3);
   failures+=parts.length>1&&parts[1].matches("\\d{1,9}")?Long.parseLong(parts[1]):1;
   if(code==null&&parts.length>2&&parts[2].matches("[A-Za-z0-9_./-]{1,200}"))code=parts[2];
  }
  Map<String,Object> status=new LinkedHashMap<>();
  status.put("failures",failures);status.put("last_failed_at",rows.getFirst().get("created_at"));status.put("code",code);
  return status;
 }
}

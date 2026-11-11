package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/** Separate from legacy rule/file bypass matching; retains individual execution provenance. */
@Service
public class BypassIdentityWriter {
 private final LedgerRepository records;
 public BypassIdentityWriter(LedgerRepository records){this.records=records;}
 @Transactional public void record(long bypassId,PullRequestScanEntity scan){
  records.lock(PullRequestBypassEntity.class,bypassId);
  for(var finding:scan.getViolations()) {
   var id=new BypassFindingIdentityEntity.Id(bypassId,finding.getId());
   if(records.find(BypassFindingIdentityEntity.class,id)!=null)continue;
   var identity=finding.getRuleIdentity();
   records.insert(new BypassFindingIdentityEntity(bypassId,finding.getId(),identity==null?null:identity.ruleId(),identity==null?null:identity.revision(),finding.getEffectiveBlocking()));
  }
 }
}

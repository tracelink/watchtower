package com.tracelink.appsec.watchtower.core.rule.report;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.*;

/** Immutable typed attention evidence, independent of current rule changes or deletion. */
@Entity @Table(name="rule_review_report_items") @IdClass(RuleReviewReportItemEntity.Id.class)
public class RuleReviewReportItemEntity {
 @jakarta.persistence.Id @Column(name="report_id",length=36) public String reportId;
 @jakarta.persistence.Id @Column(name="item_order") public Integer itemOrder;
 @Column(name="rule_id",nullable=false) public Long ruleId;
 @Column(name="rule_revision",length=64) public String revision;
 @Column(name="rule_name",length=100) public String name;
 @Column(name="module",length=64) public String module;
 @Column(name="priority",length=24) public String priority;
 @Column(name="owner",length=255) public String owner;
 @Column(name="open_reviews",nullable=false) public long openReviews;
 @Column(name="reviewed_noise",nullable=false) public boolean reviewedNoise;
 @Column(name="review_overdue",nullable=false) public boolean reviewOverdue;
 @Column(name="missing_owner",nullable=false) public boolean missingOwner;
 @Column(name="zero_matches",nullable=false) public boolean zeroMatches;
 @Column(name="missing_cwe",nullable=false) public boolean missingCwe;
 @Column(name="reviewed_sample") public Long reviewedSample;
 @Column(name="false_positives") public Long falsePositives;
 @Column(name="fp_rate") public Double fpRate;
 @Column(name="review_by") public LocalDate reviewBy;
 @Column(name="successful_engines") public Long successfulEngines;
 public RuleReviewReportItemEntity() { }
 public record Reason(String code,String label,String detail) { }
 public record Item(long ruleId,String revision,String name,String module,String priority,String owner,long openReviews,List<Reason> reasons) { }
 @SuppressWarnings("unchecked")
 public static RuleReviewReportItemEntity from(String report,int order,Map<String,Object> row) {
  var item=new RuleReviewReportItemEntity();item.reportId=report;item.itemOrder=order;item.ruleId=((Number)row.get("rule_id")).longValue();
  item.revision=(String)row.get("revision");item.name=(String)row.get("name");item.module=(String)row.get("module");item.priority=(String)row.get("priority");item.owner=(String)row.get("owner");item.openReviews=((Number)row.get("open_reviews")).longValue();
  for(var reason:(List<Map<String,Object>>)row.get("reasons"))switch((String)reason.get("code")) {
   case "CONFIRMED_NOISE" -> {item.reviewedNoise=true;item.reviewedSample=((Number)reason.get("reviewed_sample")).longValue();item.falsePositives=((Number)reason.get("false_positives")).longValue();item.fpRate=reason.get("reviewed_fp_rate") instanceof Number n?n.doubleValue():null;}
   case "REVIEW_OVERDUE" -> {item.reviewOverdue=true;item.reviewBy=LocalDate.parse((String)reason.get("review_by"));}
   case "NO_OWNER" -> item.missingOwner=true;
   case "NO_RECENT_MATCHES" -> {item.zeroMatches=true;item.successfulEngines=((Number)reason.get("completed_selections")).longValue();}
   case "NO_CWE" -> item.missingCwe=true;
   default -> throw new IllegalArgumentException("Unsupported report reason");
  }
  return item;
 }
 public Item view() {
  var reasons=new ArrayList<Reason>();
  if(reviewedNoise)reasons.add(new Reason("CONFIRMED_NOISE","Reviewed false-positive signal",falsePositives+" of "+reviewedSample+" reviewed findings were false positives in the saved 90-day window. This is a selected sample."));
  if(reviewOverdue)reasons.add(new Reason("REVIEW_OVERDUE","Review overdue","Review was due "+reviewBy+" when this report was generated."));
  if(missingOwner)reasons.add(new Reason("NO_OWNER","Missing owner","Ownership was not configured; this is not evidence of a rule-quality defect."));
  if(zeroMatches)reasons.add(new Reason("NO_RECENT_MATCHES","No recent matches",successfulEngines==null?"The legacy report recorded zero matches. Successful engine execution is unverified.":successfulEngines+" successful relevant engine executions with zero recorded matches. This is not a retirement signal or proof of per-rule coverage."));
  if(missingCwe)reasons.add(new Reason("NO_CWE","Missing CWE mapping","A missing classification does not establish missing detection coverage."));
  return new Item(ruleId,revision,name,module,priority,owner,openReviews,List.copyOf(reasons));
 }
 public static class Id implements Serializable {
  public String reportId;public Integer itemOrder;
  public Id() { }
  @Override public boolean equals(Object other){return other instanceof Id id&&Objects.equals(reportId,id.reportId)&&Objects.equals(itemOrder,id.itemOrder);}
  @Override public int hashCode(){return Objects.hash(reportId,itemOrder);}
 }
}

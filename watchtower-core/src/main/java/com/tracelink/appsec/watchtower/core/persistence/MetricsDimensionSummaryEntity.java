package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="metrics_dimension_summary")
public class MetricsDimensionSummaryEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="metric_key", nullable=false, length=64)
 public String metricKey;
 @Column(name="metric_value", nullable=false)
 public Long metricValue;
 public MetricsDimensionSummaryEntity() { }
 public MetricsDimensionSummaryEntity(String metricKey, Long metricValue) {
  this.metricKey=metricKey;
  this.metricValue=metricValue;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("metric_key",metricKey);
  values.put("metric_value",metricValue);
  return values;
 }
}

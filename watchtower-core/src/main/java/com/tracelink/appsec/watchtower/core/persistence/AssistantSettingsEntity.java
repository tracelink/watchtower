package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="assistant_settings")
public class AssistantSettingsEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="settings_id", nullable=false)
 public Integer settingsId;
 @Column(name="version", nullable=false)
 public Long version;
 @Column(name="config_json", nullable=false, columnDefinition="TEXT")
 public String configJson;
 public AssistantSettingsEntity() { }
 public AssistantSettingsEntity(Integer settingsId, Long version, String configJson) {
  this.settingsId=settingsId;
  this.version=version;
  this.configJson=configJson;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("settings_id",settingsId);
  values.put("version",version);
  values.put("config_json",configJson);
  return values;
 }
}

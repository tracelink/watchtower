package com.tracelink.appsec.watchtower.core.module;

import jakarta.persistence.*;

/** Shared execution policy; disabling never removes a module or its records. */
@Entity
@Table(name="module_settings")
public class ModuleSettingEntity {
 @Id @Column(name="module_name") private String module;
 private boolean enabled;
 @Version private long version;
 @Column(name="updated_by") private String updatedBy;
 @Column(name="updated_at") private long updatedAt;
 /** Comma-separated file types an admin chose; null means the scanner's default, empty means every file. */
 @Column(name="file_types",length=1000) private String fileTypes;
 protected ModuleSettingEntity() { }
 public ModuleSettingEntity(String module,boolean enabled) {this.module=module;this.enabled=enabled;}
 public String getModule(){return module;}
 public boolean isEnabled(){return enabled;}
 public long getVersion(){return version;}
 public String getUpdatedBy(){return updatedBy;}
 public long getUpdatedAt(){return updatedAt;}
 public String getFileTypes(){return fileTypes;}
 public void change(boolean enabled,String actor){this.enabled=enabled;this.updatedBy=actor;this.updatedAt=System.currentTimeMillis();}
 public void changeFileTypes(String fileTypes,String actor){this.fileTypes=fileTypes;this.updatedBy=actor;this.updatedAt=System.currentTimeMillis();}
}

package com.tracelink.appsec.watchtower.core.assistant.integration;

import jakarta.persistence.*;
import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;

/**
 * One AI provider's credential, managed from Assistant admin. The key is encrypted at rest by the
 * converter SCM integration credentials use; because this entity has a Spring Data repository,
 * key rotation and first-time encryption re-encrypt it with them. The key never leaves the server.
 */
@Entity @Table(name="ai_integrations")
public class AiIntegrationEntity {
 @Id @Enumerated(EnumType.STRING) @Column(name="provider",nullable=false,length=32) private AiProvider provider;
 @Column(name="api_key",length=2048) @Convert(converter=StringEncryptedAttributeConverter.class) private String apiKey;
 @Column(name="updated_by") private String updatedBy;
 @Column(name="updated_at") private Long updatedAt;
 @Column(name="health_checked_at") private Long healthCheckedAt;
 @Column(name="health_ok") private Boolean healthOk;
 @Column(name="health_error",length=500) private String healthError;
 @Version @Column(name="version",nullable=false) private long version;
 protected AiIntegrationEntity(){ }
 public AiIntegrationEntity(AiProvider provider){this.provider=provider;}
 public AiProvider getProvider(){return provider;}
 public String getApiKey(){return apiKey;}
 public boolean isConfigured(){return apiKey!=null&&!apiKey.isBlank();}
 public String getUpdatedBy(){return updatedBy;}
 public Long getUpdatedAt(){return updatedAt;}
 public Long getHealthCheckedAt(){return healthCheckedAt;}
 public Boolean getHealthOk(){return healthOk;}
 public String getHealthError(){return healthError;}
 public long getVersion(){return version;}
 /** Sets or clears the key; a changed key has not been checked yet. */
 public void setApiKey(String apiKey,String actor,long now){this.apiKey=apiKey;updatedBy=actor;updatedAt=now;healthCheckedAt=null;healthOk=null;healthError=null;}
}

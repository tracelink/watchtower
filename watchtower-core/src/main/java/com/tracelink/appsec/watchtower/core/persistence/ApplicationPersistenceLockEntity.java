package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;

/** Stable lock rows for idempotent creation and aggregate updates across application pods. */
@Entity @Table(name="application_persistence_locks")
public class ApplicationPersistenceLockEntity {
 @jakarta.persistence.Id @Column(name="lock_name",length=64) public String name;
 protected ApplicationPersistenceLockEntity() { }
}

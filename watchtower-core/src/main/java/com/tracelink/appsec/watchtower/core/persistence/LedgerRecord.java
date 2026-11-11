package com.tracelink.appsec.watchtower.core.persistence;

import java.util.Map;

/** Stable API view of a typed persistence entity. */
public interface LedgerRecord {
 Map<String,Object> values();
}

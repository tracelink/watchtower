package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
/** Immutable, bounded expiring artifacts. Deletion must include noncurrent versions. */
public interface AssistantTranscriptStore {
 void put(String key,byte[] bytes) throws IOException;
 byte[] get(String key,int maxBytes) throws IOException;
 /** Request expiry; true only when all stored versions/markers are confirmed absent. */
 boolean expire(String key) throws IOException;
 boolean shared();
 static String checkKey(String key){if(key==null||!key.matches("assistant/conversations/[a-f0-9-]{36}/[a-f0-9-]{36}/[a-f0-9-]{36}\\.json\\.gz"))throw new IllegalArgumentException("Invalid transcript key");return key;}
}

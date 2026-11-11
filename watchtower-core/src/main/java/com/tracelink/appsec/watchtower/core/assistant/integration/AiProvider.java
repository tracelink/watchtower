package com.tracelink.appsec.watchtower.core.assistant.integration;

/** AI providers whose credentials Watchtower stores; each has one ai_integrations row. */
public enum AiProvider {
 OPENAI("OpenAI");
 private final String displayName;
 AiProvider(String displayName){this.displayName=displayName;}
 public String displayName(){return displayName;}
}

package com.tracelink.appsec.watchtower.core.assistant;

import java.util.regex.Pattern;
/** Shared masking before requests, transcripts and structured human notes. */
public final class AssistantText {
 private AssistantText() { }
 private static final Pattern SECRET = Pattern.compile("(?i)(?:\\b(?:sk-[a-z0-9_-]{12,}|AKIA[A-Z0-9]{16}|gh[pousr]_[a-z0-9]{20,})|(?:password|secret|token|api[_-]?key)\\s*[:=]\\s*[\"']?[^\\s\"',;]+|-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?-----END [^-]*PRIVATE KEY-----)");
 public static String redact(String text) { return text == null ? "" : SECRET.matcher(text).replaceAll("[REDACTED]"); }
 /** Mask source before slicing lines, preserving line numbers even for multiline private keys. */
 public static String redactSource(String text) {
  var keys=Pattern.compile("-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(?:-----END [^-]*PRIVATE KEY-----|\\z)").matcher(text);
  StringBuilder result=new StringBuilder();
  while(keys.find())keys.appendReplacement(result,java.util.regex.Matcher.quoteReplacement("[REDACTED]"+"\n".repeat((int)keys.group().chars().filter(c->c=='\n').count())));
  keys.appendTail(result);return redact(result.toString());
 }
 public static String bounded(String text, int max) {
  String clean=redact(text); if(clean.length()>max) throw new IllegalArgumentException("Text exceeds limit"); return clean;
 }
}

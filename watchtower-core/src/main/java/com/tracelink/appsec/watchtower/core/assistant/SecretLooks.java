package com.tracelink.appsec.watchtower.core.assistant;

import java.util.regex.Pattern;

/**
 * One shared judgment of "this text looks like it holds a secret", used wherever a person's or a tool's
 * free text is about to go to the AI provider (a shared draft, a bypass reason, a job error). It is
 * stricter than masking: text that matches is withheld whole, so a cut or a partial match cannot leak.
 */
public final class SecretLooks {
 private SecretLooks() { }
 /** Looked at before any shortening, so a key cut in half cannot slip through. */
 public static final int LOOK_AT=4000;
 private static final Pattern PEM=Pattern.compile("-----BEGIN [^-]*-----");
 private static final Pattern TOKENS=Pattern.compile("(?i)\\bbearer\\s+[a-z0-9._~+/=-]{16,}|\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.|\\bxox[abprs]-[A-Za-z0-9-]{10,}|[a-z][a-z0-9+.-]*://[^\\s/:@]+:[^\\s/@]+@");
 /** A long unbroken run of key-like characters that mixes letters and digits. */
 private static final Pattern KEY_LIKE=Pattern.compile("[A-Za-z0-9+/_=-]{32,}");
 public static boolean looksLikeSecret(String text){
  if(text==null||text.isEmpty())return false;
  String look=text.length()>LOOK_AT?text.substring(0,LOOK_AT):text;
  if(!AssistantText.redact(look).equals(look)||PEM.matcher(look).find()||TOKENS.matcher(look).find())return true;
  var run=KEY_LIKE.matcher(look);
  while(run.find()){String token=run.group();if(token.chars().anyMatch(Character::isLetter)&&token.chars().anyMatch(Character::isDigit))return true;}
  return false;
 }
}

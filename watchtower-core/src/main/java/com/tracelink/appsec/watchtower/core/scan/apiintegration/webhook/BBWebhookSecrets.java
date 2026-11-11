package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;
import java.security.SecureRandom;
import java.util.Base64;
final class BBWebhookSecrets {
 private static final SecureRandom RANDOM=new SecureRandom();
 private BBWebhookSecrets() { }
 static String generate(){byte[] bytes=new byte[32];RANDOM.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
}

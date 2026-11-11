package com.tracelink.appsec.watchtower.core.assistant.context;

import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSettingsService;
import com.tracelink.appsec.watchtower.core.assistant.SecretLooks;

/**
 * The rule draft a person chooses to share from a designer, for one turn. It is size-capped, refused
 * (not just masked) when it looks like it holds a secret, and treated as untrusted text by the model.
 * It never becomes part of the page card and is dropped once the answer is given.
 */
@Component
public class DraftShare {
 public static final int MAX_CHARS=8000;
 /** A refusal whose words are safe and useful to show to the person, unlike a bad request in general. */
 public static class Refused extends IllegalArgumentException {
  private static final long serialVersionUID=1L;
  public Refused(String message){super(message);}
 }
 private final AssistantSettingsService settings;
 public DraftShare(AssistantSettingsService settings){this.settings=settings;}
 /** The text to send, or a plain reason it cannot be shared. */
 public String accept(String draft){
  if(!settings.get().settings().isFeatureOn(AssistantFeature.CONTEXT_CARDS))throw new Refused("Sharing a draft is turned off. An Assistant Admin can turn on AI page context.");
  String text=draft==null?"":draft.strip();
  if(text.isEmpty())throw new Refused("There is no draft to share.");
  if(text.length()>MAX_CHARS)throw new Refused("This draft is too long to share ("+MAX_CHARS+" characters at most).");
  if(SecretLooks.looksLikeSecret(text))throw new Refused("This draft looks like it contains a secret, so it was not shared. Remove it and try again.");
  return text;
 }
}

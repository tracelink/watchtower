package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.Set;

/** Builds the card for one kind of page from ids, using only what the person may read. */
public interface ContextProvider {
 String kind();
 /** Grants the person needs, all of which are checked before {@link #resolve} is called. */
 Set<String> grants();
 /** Never trusts the ids: a wrong or unknown id gives an unavailable card, and a secret finding a blocked one. */
 ContextCard resolve(ContextRequest.Ids ids);
}

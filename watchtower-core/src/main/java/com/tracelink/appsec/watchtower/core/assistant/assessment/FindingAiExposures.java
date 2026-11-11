package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.time.Clock;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Remembers the first time each person saw an AI opinion about a finding, from the stored assessment
 * or from chat. Agreement with human judgments counts only judgments made before that moment.
 */
@Component
public class FindingAiExposures {
 public static final String ASSESSMENT="ASSESSMENT",CHAT="CHAT";
 private static final Set<String> SOURCES=Set.of(ASSESSMENT,CHAT);
 private final FindingAiExposureRepository exposures;private final TransactionTemplate tx;private final Clock clock;
 @Autowired
 public FindingAiExposures(FindingAiExposureRepository exposures,PlatformTransactionManager tm){this(exposures,tm,Clock.systemUTC());}
 public FindingAiExposures(FindingAiExposureRepository exposures,PlatformTransactionManager tm,Clock clock){this.exposures=exposures;this.tx=new TransactionTemplate(tm);this.tx.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);this.clock=clock;}
 /** The recorded first sightings for these findings. */
 public java.util.List<FindingAiExposureEntity> forFindings(java.util.Collection<String> occurrenceKeys){return exposures.findByOccurrenceKeyIn(occurrenceKeys);}
 /** Records many findings for one person with one read, writing only the ones not yet on record. */
 public void recordAll(java.util.Collection<String> occurrenceKeys,String viewer,String source){
  if(occurrenceKeys.isEmpty())return;
  var known=new java.util.HashSet<String>();
  for(var e:exposures.findByOccurrenceKeyIn(occurrenceKeys))if(e.getViewer().equals(viewer))known.add(e.getOccurrenceKey());
  for(String key:occurrenceKeys)if(!known.contains(key))record(key,viewer,source);
 }
 /** Keeps the first sighting; later ones for the same person and finding change nothing. */
 public void record(String occurrenceKey,String viewer,String source){
  if(occurrenceKey==null||occurrenceKey.isBlank()||occurrenceKey.length()>64||viewer==null||viewer.isBlank()||!SOURCES.contains(source))throw new IllegalArgumentException("Invalid AI exposure");
  var key=new FindingAiExposureEntity.Key(occurrenceKey,viewer);
  if(exposures.existsById(key))return;
  try{tx.executeWithoutResult(s->exposures.saveAndFlush(new FindingAiExposureEntity(occurrenceKey,viewer,source,clock.millis())));}
  catch(DataIntegrityViolationException e){/* recorded by a concurrent request of the same person; its own transaction keeps any caller's intact */}
 }
}

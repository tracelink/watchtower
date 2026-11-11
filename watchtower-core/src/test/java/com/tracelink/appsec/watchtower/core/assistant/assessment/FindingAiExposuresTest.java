package com.tracelink.appsec.watchtower.core.assistant.assessment;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;

/** S0: who first saw an AI opinion about a finding, by finding and person, so blind agreement stays honest. */
class FindingAiExposuresTest {
 R1Database database;FindingAiExposures exposures;final AtomicReference<Instant> now=new AtomicReference<>(Instant.parse("2026-10-24T09:00:00Z"));
 @BeforeEach void setup(){
  database=new R1Database();
  Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  exposures=new FindingAiExposures(database.repository(FindingAiExposureRepository.class),database.tx,clock);
 }
 @AfterEach void close(){database.close();}
 @Test void theFirstSightingIsKeptAndLaterOnesChangeNothing(){
  exposures.record("o".repeat(64),"alice",FindingAiExposures.CHAT);
  now.set(now.get().plusSeconds(60));
  exposures.record("o".repeat(64),"alice",FindingAiExposures.ASSESSMENT);
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class));
  assertEquals("CHAT",database.jdbc.queryForObject("SELECT source FROM finding_ai_exposure",String.class));
  assertEquals(Instant.parse("2026-10-24T09:00:00Z").toEpochMilli(),database.jdbc.queryForObject("SELECT first_seen_at FROM finding_ai_exposure",Long.class));
 }
 @Test void eachPersonAndEachFindingHasItsOwnRow(){
  exposures.record("a".repeat(64),"alice",FindingAiExposures.CHAT);exposures.record("a".repeat(64),"bob",FindingAiExposures.CHAT);exposures.record("b".repeat(64),"alice",FindingAiExposures.ASSESSMENT);
  assertEquals(3,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class));
 }
 @Test void aBadSourceOrMissingNameIsRefusedBeforeAnythingIsWritten(){
  assertThrows(IllegalArgumentException.class,()->exposures.record("a".repeat(64),"alice","TELEPATHY"));
  assertThrows(IllegalArgumentException.class,()->exposures.record("a".repeat(64)," ",FindingAiExposures.CHAT));
  assertThrows(IllegalArgumentException.class,()->exposures.record(null,"alice",FindingAiExposures.CHAT));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class));
 }
}

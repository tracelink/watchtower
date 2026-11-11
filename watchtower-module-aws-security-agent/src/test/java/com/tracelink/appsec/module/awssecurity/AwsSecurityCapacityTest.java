package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AwsSecurityCapacityTest {
    @Test void administratorOverrideIsSharedWithAdmissionAndCanChangeWhileReviewsAreActive() {
        var permits = mock(AwsSecurityPermitRepository.class);
        var audit = mock(AwsSecurityAuditRepository.class);
        var control = new AwsSecurityPermit(); control.id = 1;
        when(permits.findById(1)).thenReturn(Optional.of(control));
        when(permits.locked()).thenReturn(control);
        var capacity = new AwsSecurityCapacity(2, permits, audit);

        assertEquals(new AwsSecurityCapacity.Snapshot(2, 2, false), capacity.snapshot());
        capacity.save(3, "administrator");
        assertEquals(new AwsSecurityCapacity.Snapshot(3, 2, true), capacity.snapshot());
        assertEquals(3, capacity.limit(control));
        verify(audit).save(argThat(event -> "capacity-changed".equals(event.action)
            && "administrator".equals(event.actor) && "concurrent-reviews:3".equals(event.resourceId)));

        capacity.save(1, "administrator");
        assertEquals(1, capacity.limit(control));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> capacity.save(0, "administrator"));
        assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> capacity.save(6, "administrator"));
        assertEquals(1, capacity.limit());
    }

    @Test void twoPodsCanReserveDistinctSlotsAndAThirdWaitsForTerminalProof() {
        var runs = mock(AwsSecurityRunRepository.class);
        var permits = mock(AwsSecurityPermitRepository.class);
        var slots = new ArrayList<AwsSecurityPermit>();
        for (int id = 1; id <= 5; id++) { var slot = new AwsSecurityPermit(); slot.id = id; slots.add(slot); }
        var records = new HashMap<String, AwsSecurityRun>();
        for (String id : List.of("first", "second", "third")) {
            var run = new AwsSecurityRun(); run.id = id; run.stage = AwsSecurityRun.Stage.QUEUED;
            run.createdAt = 1; run.deadlineAt = 60_001;
            run.parentType = "pull_request"; records.put(id, run);
        }
        when(permits.locked()).thenReturn(slots.getFirst());
        when(permits.findAllByOrderByIdAsc()).thenReturn(slots);
        when(runs.locked(anyString())).thenAnswer(call -> Optional.ofNullable(records.get(call.getArgument(0))));
        when(runs.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));
        var persistence = new AwsSecurityPersistence(runs, permits, new AwsSecurityCapacity(2));
        long now = System.currentTimeMillis();

        var first = persistence.claim("first", "pod-a", now).orElseThrow();
        persistence.claim("second", "pod-b", now).orElseThrow();
        assertEquals("first", slots.get(0).runId);
        assertEquals("second", slots.get(1).runId);
        assertTrue(persistence.claim("third", "pod-c", now).isEmpty());
        assertEquals("Waiting for AWS capacity", records.get("third").statusReason);

        first.stage = AwsSecurityRun.Stage.FAILED;
        first.jobId = "accepted-job";
        persistence.release("first", "pod-a", first.fence);
        assertEquals("first", slots.get(0).runId);
        assertTrue(persistence.claim("third", "pod-c", now).isEmpty());

        first = persistence.claim("first", "pod-a", now).orElseThrow();
        first.providerTerminal = true;
        persistence.release("first", "pod-a", first.fence);
        assertNull(slots.get(0).runId);
        persistence.claim("third", "pod-c", now).orElseThrow();
        assertEquals("third", slots.get(0).runId);
        assertNull(records.get("third").statusReason);
        assertEquals(now + 60_000, records.get("third").deadlineAt);
    }
}

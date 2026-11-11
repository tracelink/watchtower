package com.tracelink.appsec.watchtower.core.feedback;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class FindingReviewServiceTest {
    @Test void returnNavigationIsBoundToTheSameApplicationReport() {
        String report = "/scan/report/1";
        for (String invalid : new String[]{"https://evil.test", "//evil.test", "/\\evil.test", "/scan/report/2",
                "/scan/report/1/../2", "/scan/report/1\r\nLocation:evil", "/%2f%2fevil.test", "javascript:alert(1)", "?next=/", ""}) {
            assertEquals(report, FindingReviewService.safeReturn(invalid, report), invalid);
        }
        String local = report + "?reviewFinding=7&reviewSearch=authentication#findings";
        assertEquals(local, FindingReviewService.safeReturn(local, report));
        assertEquals(report, FindingReviewService.safeReturn(null, report));
    }
}

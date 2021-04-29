package com.tracelink.appsec.watchtower.core.scan.scm.pr.data;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DiffLineTest {

    @Test
    public void testDAO() {
        int lineNum = 2;
        DiffType type = DiffType.EXISTING;
        DiffLine dl = new DiffLine(lineNum, type);
        Assertions.assertEquals(lineNum, dl.getLineNum());
        Assertions.assertEquals(type, dl.getType());
    }

}

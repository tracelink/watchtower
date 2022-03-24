package com.tracelink.appsec.watchtower.core.scan.code.pr.data;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.pr.data.DiffLine;
import com.tracelink.appsec.watchtower.core.scan.code.pr.data.DiffType;

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

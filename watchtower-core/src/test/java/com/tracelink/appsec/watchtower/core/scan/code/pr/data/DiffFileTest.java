package com.tracelink.appsec.watchtower.core.scan.code.pr.data;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.pr.data.DiffFile;

public class DiffFileTest {

    @Test
    public void testDAO() {
        String path = "/path/to/file";
        String diffid = "3";
        DiffFile diff = new DiffFile(path, diffid);
        Assertions.assertEquals(path, diff.getPath());
        Assertions.assertEquals(diffid, diff.getDiffId());
    }

    @Test
    public void testDiff() throws IOException {
        StringBuilder file = new StringBuilder();
        file.append("@@\n");
        file.append("+ some file\n");
        file.append("- lines\n");
        file.append("  withmultiple\n");
        DiffFile diff = new DiffFile("", "");
        diff.parseDiff(IOUtils.toInputStream(file.toString(), Charset.defaultCharset()));
        Assertions.assertEquals(true, diff.isLineChanged(1));
        Assertions.assertEquals(false, diff.isLineChanged(2));
    }
}
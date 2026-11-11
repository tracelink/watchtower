package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;

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

    private DiffFile parse(String diff) throws IOException {
        DiffFile diffFile = new DiffFile("", "");
        diffFile.parseDiff(IOUtils.toInputStream(diff, Charset.defaultCharset()));
        return diffFile;
    }

    @Test
    public void testHunkHeaderSetsStartingLineNumber() throws IOException {
        // A change deep in a file must be reported at its real line number, not at
        // line 1. Only correct if the "+43" in the hunk header is honoured.
        String diff = "diff --git a/Foo.java b/Foo.java\n"
                + "index 1111111..2222222 100644\n"
                + "--- a/Foo.java\n"
                + "+++ b/Foo.java\n"
                + "@@ -42,0 +43,1 @@\n"
                + "+    int added = 1;\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(43));
        Assertions.assertFalse(diffFile.isLineChanged(1));
    }

    @Test
    public void testMultipleHunksEachStartAtTheirOwnOffset() throws IOException {
        String diff = "@@ -10,2 +10,3 @@\n"
                + " context10\n"
                + "+added11\n"
                + " context12\n"
                + "@@ -50,1 +51,2 @@\n"
                + "+added51\n"
                + " context52\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(11));
        Assertions.assertTrue(diffFile.isLineChanged(51));
        Assertions.assertTrue(diffFile.isLineExisting(10));
        Assertions.assertTrue(diffFile.isLineExisting(52));
        // The second "@@" header must not be counted as a line of source.
        Assertions.assertFalse(diffFile.isLineExisting(13));
        Assertions.assertFalse(diffFile.isLineChanged(2));
    }

    @Test
    public void testHunkHeaderWithoutLineCounts() throws IOException {
        // The ",count" part of a hunk header is optional in unified diff format.
        String diff = "@@ -1 +1 @@\n"
                + "-old\n"
                + "+new\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(1));
        Assertions.assertFalse(diffFile.isLineChanged(2));
    }

    @Test
    public void testFileHeadersBetweenHunksAreNotCountedAsSource() throws IOException {
        // "+++ b/B.java" starts with '+' and "--- a/B.java" starts with '-'. Neither is
        // a line of source and neither may consume a line number.
        String diff = "diff --git a/A.java b/A.java\n"
                + "--- a/A.java\n"
                + "+++ b/A.java\n"
                + "@@ -1,1 +1,2 @@\n"
                + "+addedA\n"
                + "diff --git a/B.java b/B.java\n"
                + "--- a/B.java\n"
                + "+++ b/B.java\n"
                + "@@ -100,1 +100,2 @@\n"
                + "+addedB\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(1));
        Assertions.assertTrue(diffFile.isLineChanged(100));
        Assertions.assertFalse(diffFile.isLineChanged(2));
        Assertions.assertFalse(diffFile.isLineChanged(3));
    }

    @Test
    public void testEmptyLineInDiffDoesNotThrow() throws IOException {
        // An empty line is a well-formed part of a diff body. Reading charAt(0) on it
        // throws StringIndexOutOfBoundsException.
        String diff = "@@ -1,3 +1,4 @@\n"
                + " first\n"
                + "\n"
                + "+added\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(3));
        Assertions.assertTrue(diffFile.isLineExisting(1));
    }

    @Test
    public void testNoNewlineMarkerIsNotCountedAsSource() throws IOException {
        String diff = "@@ -1,1 +1,1 @@\n"
                + "-old\n"
                + "+new\n"
                + "\\ No newline at end of file\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(1));
        Assertions.assertFalse(diffFile.isLineExisting(2));
    }

    @Test
    public void testDeletedLinesDoNotConsumeLineNumbers() throws IOException {
        // Deleted lines are absent from the new file, so they must not advance the
        // line counter. "+kept" is line 2 of the new file, not line 4.
        String diff = "@@ -1,4 +1,2 @@\n"
                + " first\n"
                + "-gone1\n"
                + "-gone2\n"
                + "+kept\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.isLineChanged(2));
        Assertions.assertFalse(diffFile.isLineChanged(4));
    }

    @Test
    public void testDeletionOnlyHunkStillCountsAsChanged() throws IOException {
        // At context=0 a file whose only change is a deletion has no added lines and no
        // context lines, so nothing is recorded against a line number. The file is
        // still part of the pull request though, and hasDiffs() is what
        // PRScanAgent.identifyNewViolations() uses to decide whether a violated file
        // was touched by the PR at all. Returning false here silently drops every
        // violation in the file.
        String diff = "@@ -10,3 +9,0 @@\n"
                + "-gone1\n"
                + "-gone2\n"
                + "-gone3\n";

        DiffFile diffFile = parse(diff);

        Assertions.assertTrue(diffFile.hasDiffs());
        Assertions.assertFalse(diffFile.isLineChanged(9));
    }

    @Test
    public void testEmptyDiffHasNoDiffs() throws IOException {
        // No hunks at all means Bitbucket reported no changes for this file, so it is
        // not part of the pull request.
        Assertions.assertFalse(parse("").hasDiffs());
    }

    @Test
    public void testFileHeadersWithoutHunksHaveNoDiffs() throws IOException {
        String diff = "diff --git a/Foo.java b/Foo.java\n"
                + "index 1111111..2222222 100644\n"
                + "--- a/Foo.java\n"
                + "+++ b/Foo.java\n";

        Assertions.assertFalse(parse(diff).hasDiffs());
    }

    /**
     * The gate for switching {@code BBCloudApi.getGitDiffFile()} from
     * {@code context=100000} to {@code context=0}: the same change expressed with zero
     * context and with whole-file context must yield the same modified line numbers.
     * Without a hunk-header-aware parser these two disagree, which is why the large
     * context value was load-bearing.
     */
    @Test
    public void testZeroContextAndFullContextAgreeOnModifiedLines() throws IOException {
        String zeroContext = "@@ -3,0 +4,1 @@\n"
                + "+    added line\n";

        String fullContext = "@@ -1,5 +1,6 @@\n"
                + " line1\n"
                + " line2\n"
                + " line3\n"
                + "+    added line\n"
                + " line5\n"
                + " line6\n";

        DiffFile zero = parse(zeroContext);
        DiffFile full = parse(fullContext);

        for (int lineNum = 1; lineNum <= 6; lineNum++) {
            Assertions.assertEquals(full.isLineChanged(lineNum), zero.isLineChanged(lineNum),
                    "context=0 and context=100000 disagree on line " + lineNum);
        }
        Assertions.assertTrue(zero.isLineChanged(4));
    }

    // parseMultiFileDiff() - IMPROVEMENT_PLAN.md item 1.0b, the prerequisite item 2.3 needs
    // to split Bitbucket's whole-PR diff response into one DiffFile per changed file.

    private Map<String, DiffFile> parseMulti(String diff) throws IOException {
        return DiffFile.parseMultiFileDiff(IOUtils.toInputStream(diff, Charset.defaultCharset()),
                "diff-id");
    }

    @Test
    public void testMultiFileDiffOfEmptyStreamIsEmptyMap() throws IOException {
        Assertions.assertTrue(parseMulti("").isEmpty());
    }

    @Test
    public void testMultiFileDiffSingleFile() throws IOException {
        String diff = "diff --git a/Foo.java b/Foo.java\n"
                + "index 1111111..2222222 100644\n"
                + "--- a/Foo.java\n"
                + "+++ b/Foo.java\n"
                + "@@ -42,0 +43,1 @@\n"
                + "+    int added = 1;\n";

        Map<String, DiffFile> diffs = parseMulti(diff);

        Assertions.assertEquals(1, diffs.size());
        DiffFile foo = diffs.get("Foo.java");
        Assertions.assertNotNull(foo);
        Assertions.assertEquals("diff-id", foo.getDiffId());
        Assertions.assertTrue(foo.isLineChanged(43));
    }

    @Test
    public void testMultiFileDiffSplitsEachFileIntoItsOwnDiffFile() throws IOException {
        // Same fixture as testFileHeadersBetweenHunksAreNotCountedAsSource, but this time
        // each file must get its own independent line numbering rather than sharing one.
        String diff = "diff --git a/A.java b/A.java\n"
                + "--- a/A.java\n"
                + "+++ b/A.java\n"
                + "@@ -1,1 +1,2 @@\n"
                + "+addedA\n"
                + "diff --git a/B.java b/B.java\n"
                + "--- a/B.java\n"
                + "+++ b/B.java\n"
                + "@@ -100,1 +100,2 @@\n"
                + "+addedB\n";

        Map<String, DiffFile> diffs = parseMulti(diff);

        Assertions.assertEquals(2, diffs.size());
        Assertions.assertTrue(diffs.get("A.java").isLineChanged(1));
        Assertions.assertFalse(diffs.get("A.java").isLineChanged(100));
        Assertions.assertTrue(diffs.get("B.java").isLineChanged(100));
        Assertions.assertFalse(diffs.get("B.java").isLineChanged(1));
    }

    @Test
    public void testMultiFileDiffBinaryFileHasNoLineDiffsButIsMarkedChanged() throws IOException {
        String diff = "diff --git a/image.png b/image.png\n"
                + "index 1111111..2222222 100644\n"
                + "Binary files a/image.png and b/image.png differ\n"
                + "diff --git a/Foo.java b/Foo.java\n"
                + "--- a/Foo.java\n"
                + "+++ b/Foo.java\n"
                + "@@ -1,1 +1,2 @@\n"
                + "+added\n";

        Map<String, DiffFile> diffs = parseMulti(diff);

        Assertions.assertEquals(2, diffs.size());
        DiffFile image = diffs.get("image.png");
        Assertions.assertNotNull(image);
        Assertions.assertTrue(image.hasDiffs());
        Assertions.assertFalse(image.isLineChanged(1));
        // The binary section must not leak into the following file's line numbering.
        Assertions.assertTrue(diffs.get("Foo.java").isLineChanged(1));
    }

    @Test
    public void testMultiFileDiffRenamedFileWithContentChangeUsesNewPath() throws IOException {
        String diff = "diff --git a/old/Path.java b/new/Path.java\n"
                + "similarity index 85%\n"
                + "rename from old/Path.java\n"
                + "rename to new/Path.java\n"
                + "index 1111111..2222222 100644\n"
                + "--- a/old/Path.java\n"
                + "+++ b/new/Path.java\n"
                + "@@ -1,1 +1,2 @@\n"
                + "+added\n";

        Map<String, DiffFile> diffs = parseMulti(diff);

        Assertions.assertEquals(1, diffs.size());
        Assertions.assertNull(diffs.get("old/Path.java"));
        Assertions.assertTrue(diffs.get("new/Path.java").isLineChanged(1));
    }

    @Test
    public void testMultiFileDiffDeletedFileKeyedByFormerPath() throws IOException {
        String diff = "diff --git a/gone.txt b/gone.txt\n"
                + "deleted file mode 100644\n"
                + "index 1111111..0000000\n"
                + "--- a/gone.txt\n"
                + "+++ /dev/null\n"
                + "@@ -1,3 +0,0 @@\n"
                + "-line1\n"
                + "-line2\n"
                + "-line3\n";

        Map<String, DiffFile> diffs = parseMulti(diff);

        Assertions.assertEquals(1, diffs.size());
        DiffFile gone = diffs.get("gone.txt");
        Assertions.assertNotNull(gone);
        Assertions.assertTrue(gone.hasDiffs());
    }
}
package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data;

/**
 * A data object denoting if a line is modified or old
 *
 * @author csmith
 */
public class DiffLine {
    private int lineNum;
    private DiffType type;

    public DiffLine(int lineNum, DiffType type) {
        this.lineNum = lineNum;
        this.type = type;
    }

    public int getLineNum() {
        return lineNum;
    }

    public DiffType getType() {
        return type;
    }

}

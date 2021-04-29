package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.Writer;

/**
 * a writer that does nothing. doesn't write, doesn't flush, doesn't execute
 * code
 *
 * @author csmith
 */
public class NoopWriter extends Writer {

	@Override
	public void write(char[] cbuf, int off, int len) throws IOException {
	}

	@Override
	public void flush() throws IOException {
	}

	@Override
	public void close() throws IOException {
	}

}

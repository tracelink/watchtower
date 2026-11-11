package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Turns a {@link RepoScanReport} into gzip-compressed JSON and back. Unknown fields are ignored
 * when reading, so a newer report format can still be read by an older pod.
 *
 * @author Watchtower
 */
public final class RepoReportCodec {

	public static final String CONTENT_TYPE = "application/json";

	/** A decompressed report larger than this is refused rather than read into memory. */
	static final long MAX_REPORT_BYTES = 64L * 1024 * 1024;

	private static final ObjectMapper MAPPER = new ObjectMapper()
			.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

	private RepoReportCodec() {
	}

	public static byte[] encode(RepoScanReport report) throws IOException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (OutputStream gzip = new GZIPOutputStream(bytes)) {
			MAPPER.writeValue(gzip, report);
		}
		return bytes.toByteArray();
	}

	public static RepoScanReport decode(byte[] content) throws IOException {
		try (InputStream gzip = new GZIPInputStream(new ByteArrayInputStream(content));
				InputStream bounded = new BoundedInputStream(gzip, MAX_REPORT_BYTES)) {
			return MAPPER.readValue(bounded, RepoScanReport.class);
		}
	}

	/**
	 * Stops a compressed report that expands beyond the limit from exhausting memory.
	 */
	private static final class BoundedInputStream extends InputStream {

		private final InputStream in;

		private long remaining;

		BoundedInputStream(InputStream in, long limit) {
			this.in = in;
			this.remaining = limit;
		}

		@Override
		public int read() throws IOException {
			if (remaining <= 0) {
				throw new IOException("Report is larger than " + MAX_REPORT_BYTES + " bytes");
			}
			int b = in.read();
			if (b >= 0) {
				remaining--;
			}
			return b;
		}

		@Override
		public int read(byte[] buffer, int offset, int length) throws IOException {
			if (remaining <= 0) {
				throw new IOException("Report is larger than " + MAX_REPORT_BYTES + " bytes");
			}
			int read = in.read(buffer, offset, (int) Math.min(length, remaining));
			if (read > 0) {
				remaining -= read;
			}
			return read;
		}

		@Override
		public void close() throws IOException {
			in.close();
		}
	}
}

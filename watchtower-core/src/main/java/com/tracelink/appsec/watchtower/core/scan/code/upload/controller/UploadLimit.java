package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import java.util.Locale;

/**
 * The server's multipart limits for the upload form (UAT #30): a short chip ("Up to 250 MB") and
 * the exact limits for its hover text. A negative size means no limit.
 */
record UploadLimit(long fileBytes, long requestBytes) {

	private static final double BYTES_PER_MIB = 1_048_576d;

	/** The limit that actually applies: the smaller of the file and whole-request limits. */
	long effectiveBytes() {
		if (fileBytes < 0) {
			return requestBytes;
		}
		return requestBytes < 0 ? fileBytes : Math.min(fileBytes, requestBytes);
	}

	String summary() {
		long effective = effectiveBytes();
		return effective < 0 ? "No size limit" : "Up to " + Math.round(effective / BYTES_PER_MIB) + " MB";
	}

	String detail() {
		if (fileBytes < 0 && requestBytes < 0) {
			return "The server sets no upload size limit.";
		}
		String file = fileBytes < 0 ? "No file limit." : "File limit " + mib(fileBytes) + ".";
		String request = requestBytes < 0 ? ""
				: " The whole request, form fields included, must also stay under "
						+ Math.round(requestBytes / BYTES_PER_MIB) + " MiB.";
		return file + request;
	}

	private static String mib(long bytes) {
		return String.format(Locale.ROOT, "%d MiB (%,d bytes)", Math.round(bytes / BYTES_PER_MIB), bytes);
	}
}

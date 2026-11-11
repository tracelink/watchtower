package com.tracelink.appsec.module.regex.scanner;

/**
 * The same characters as the text it wraps, but reading them past a deadline throws
 * {@linkplain MatchTimeoutException}. A regular expression that backtracks without end keeps
 * reading characters, so handing the matcher this instead of the plain line stops it. The clock
 * is only looked at every {@value #CHECK_INTERVAL} reads, so ordinary matches never reach it.
 */
final class DeadlineCharSequence implements CharSequence {

	private static final int CHECK_INTERVAL = 1 << 16;

	private final CharSequence inner;
	private final long deadlineNanos;
	private int reads;

	DeadlineCharSequence(CharSequence inner, long deadlineNanos) {
		this.inner = inner;
		this.deadlineNanos = deadlineNanos;
	}

	@Override
	public char charAt(int index) {
		reads++;
		if (reads % CHECK_INTERVAL == 0 && System.nanoTime() - deadlineNanos > 0) {
			throw new MatchTimeoutException();
		}
		return inner.charAt(index);
	}

	@Override
	public int length() {
		return inner.length();
	}

	@Override
	public CharSequence subSequence(int start, int end) {
		return new DeadlineCharSequence(inner.subSequence(start, end), deadlineNanos);
	}

	@Override
	public String toString() {
		return inner.toString();
	}

	/** Thrown when a match ran past its deadline. Carries no stack trace: it is control flow. */
	static final class MatchTimeoutException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		MatchTimeoutException() {
			super("The regular expression took too long", null, false, false);
		}
	}
}

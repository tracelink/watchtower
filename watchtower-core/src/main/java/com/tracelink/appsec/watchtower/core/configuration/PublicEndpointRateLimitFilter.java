package com.tracelink.appsec.watchtower.core.configuration;

import java.io.IOException;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** A bounded, per-client rate limit for unauthenticated state-changing endpoints. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class PublicEndpointRateLimitFilter extends OncePerRequestFilter {
	private static final int MAX_CLIENT_KEYS = 50_000;

	/** Default budget for Bitbucket comment deliveries; see {@link #COMMENT_EVENT}. */
	static final int DEFAULT_COMMENT_LIMIT = 300;

	/**
	 * Bitbucket delivers this for every pull request comment in the workspace, so it gets its own
	 * bucket: busy comment threads must never use up the budget scan deliveries need. A caller
	 * that fakes the header only moves itself into that bucket, which has a limit too.
	 */
	static final String COMMENT_EVENT = "pullrequest:comment_created";

	private final int requestLimit;
	private final int commentLimit;
	private final long windowMillis;
	private final Clock clock;
	private final ConcurrentMap<String, Window> windows = new ConcurrentHashMap<>();

	@Autowired
	public PublicEndpointRateLimitFilter(
			@Value("${watchtower.security.public-rate-limit.requests:60}") int requestLimit,
			@Value("${watchtower.security.public-rate-limit.comment-requests:"
					+ DEFAULT_COMMENT_LIMIT + "}") int commentLimit,
			@Value("${watchtower.security.public-rate-limit.window-seconds:60}") long windowSeconds) {
		this(requestLimit, commentLimit, windowSeconds, Clock.systemUTC());
	}

	PublicEndpointRateLimitFilter(int requestLimit, long windowSeconds) {
		this(requestLimit, DEFAULT_COMMENT_LIMIT, windowSeconds, Clock.systemUTC());
	}

	PublicEndpointRateLimitFilter(int requestLimit, int commentLimit, long windowSeconds,
			Clock clock) {
		if (requestLimit < 1 || commentLimit < 1 || windowSeconds < 1) {
			throw new IllegalArgumentException("Rate limit and window must be positive");
		}
		this.requestLimit = requestLimit;
		this.commentLimit = commentLimit;
		this.windowMillis = windowSeconds * 1000;
		this.clock = clock;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		if (!"POST".equalsIgnoreCase(request.getMethod())) return true;
		String path = request.getRequestURI().substring(request.getContextPath().length());
		return !(path.equals("/login") || path.equals("/register")
				|| path.equals("/rest/csp/report") || path.startsWith("/rest/scan/"));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		long now = clock.millis();
		if (windows.size() >= MAX_CLIENT_KEYS) removeExpired(now);

		String endpoint = endpointGroup(request);
		String client = request.getRemoteAddr();
		String key = endpoint + ':' + client;
		if (windows.size() >= MAX_CLIENT_KEYS && !windows.containsKey(key)) {
			key = endpoint + ":overflow";
		}
		Window current = windows.compute(key, (ignored, prior) ->
				prior == null || prior.expiresAt() <= now
						? new Window(1, now + windowMillis)
						: new Window(prior.count() + 1, prior.expiresAt()));
		int limit = isCommentDelivery(request) ? commentLimit : requestLimit;
		if (current.count() > limit) {
			long retryAfter = Math.max(1, (current.expiresAt() - now + 999) / 1000);
			response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
			response.setHeader("Retry-After", Long.toString(retryAfter));
			response.setHeader("Cache-Control", "no-store");
			response.setContentType("text/plain");
			response.getWriter().write("Too many requests");
			return;
		}
		filterChain.doFilter(request, response);
	}

	private String endpointGroup(HttpServletRequest request) {
		String path = request.getRequestURI().substring(request.getContextPath().length());
		if (isCommentDelivery(request)) {
			// Per integration (the path names it): Bitbucket delivers every workspace from the
			// same few addresses, so one busy workspace must not use up another's budget.
			return path + "#comment";
		}
		return path.startsWith("/rest/scan/") ? "/rest/scan" : path;
	}

	private static boolean isCommentDelivery(HttpServletRequest request) {
		String path = request.getRequestURI().substring(request.getContextPath().length());
		return path.startsWith("/rest/scan/")
				&& COMMENT_EVENT.equals(request.getHeader("X-Event-Key"));
	}

	private void removeExpired(long now) {
		windows.entrySet().removeIf(entry -> entry.getValue().expiresAt() <= now);
	}

	private record Window(int count, long expiresAt) { }
}

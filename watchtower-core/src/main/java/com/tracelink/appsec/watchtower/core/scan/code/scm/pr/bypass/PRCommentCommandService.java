package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.CustomizableThreadFactory;
import org.springframework.stereotype.Service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRCommentFormat;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

/**
 * Handles {@code /watchtower bypass <reason>} pull request comments (§4.18): the developer's
 * request becomes a normal bypass request (§4.17), and Watchtower replies to the comment with the
 * outcome.
 * <p>
 * Kept away from scanning: ordinary comments are dropped by a substring check before anything is
 * parsed. Possible commands are parsed once to reserve their comment id, then run on this
 * service's own single thread with a small bounded queue, never on the scan executor. A full queue drops the command (logged) rather than slow the webhook.
 *
 * @author Watchtower
 */
@Service
public class PRCommentCommandService implements DisposableBean {

	private static final Logger LOG = LoggerFactory.getLogger(PRCommentCommandService.class);

	/** Commands waiting to run; more are dropped. Each needs a human to type it. */
	static final int QUEUE_CAPACITY = 50;

	/** Best-effort per-pod suppression; bounded memory, no claim of cross-pod exactly-once delivery. */
	static final long COMMENT_DEDUP_MILLIS = 300_000;
	static final int MAX_RECENT_COMMENTS = 10_000;
	private record CommentKey(String label, String repo, String prId, long commentId) { }
	private final Map<CommentKey, Long> recentComments = new LinkedHashMap<>();
	private final Counter duplicateComments;

	/**
	 * A pull request gets at most one refusal reply per this period. Replies use the same
	 * Bitbucket account and quota as scan comments and approvals, so repeating the command must
	 * not spend it. A request that is made is always answered.
	 */
	static final long REFUSAL_COOLDOWN_MILLIS = 60_000;

	/** Above this many remembered pull requests, expired cooldowns are forgotten. */
	private static final int MAX_COOLDOWNS = 1_000;

	/** The longest requester name kept, as the requested_by column allows. */
	private static final int MAX_NAME_LENGTH = 255;

	private final PRScanResultService resultService;
	private final PRBypassRequestService requestService;
	private final ApiIntegrationService apiService;
	private final String publicUrl;
	private final Executor executor;
	private final LongSupplier clock;
	private final Map<String, Long> lastRefusal = new ConcurrentHashMap<>();

	private PRCommentDeliveryClaims deliveryClaims;
	@Autowired public void setDeliveryClaims(PRCommentDeliveryClaims claims){deliveryClaims=claims;}

	@Autowired
	public PRCommentCommandService(PRScanResultService resultService,
			PRBypassRequestService requestService, ApiIntegrationService apiService,
			@Value("${watchtower.publicUrl:#{null}}") String publicUrl, MeterRegistry meters) {
		this(resultService, requestService, apiService, publicUrl, new ThreadPoolExecutor(1, 1, 0,
				TimeUnit.SECONDS, new ArrayBlockingQueue<>(QUEUE_CAPACITY),
				new CustomizableThreadFactory("wt-pr-comment-")), System::currentTimeMillis, meters);
	}

	PRCommentCommandService(PRScanResultService resultService,
			PRBypassRequestService requestService, ApiIntegrationService apiService,
			String publicUrl, Executor executor, LongSupplier clock) {
		this(resultService, requestService, apiService, publicUrl, executor, clock, new SimpleMeterRegistry());
	}

	PRCommentCommandService(PRScanResultService resultService,
			PRBypassRequestService requestService, ApiIntegrationService apiService,
			String publicUrl, Executor executor, LongSupplier clock, MeterRegistry meters) {
		this.duplicateComments = meters.counter("watchtower.webhook.comment.duplicates");
		this.resultService = resultService;
		this.requestService = requestService;
		this.apiService = apiService;
		this.publicUrl = publicUrl;
		this.executor = executor;
		this.clock = clock;
	}

	/**
	 * Queues a comment delivery if it may hold a command. Returns at once; never throws.
	 *
	 * @param pr   the pull request the comment is on (apiLabel, repo, id)
	 * @param body the raw {@code pullrequest:comment_created} webhook body
	 * @return true if queued; false for noncommands, duplicate deliveries or a full queue
	 */
	public boolean submit(PullRequest pr, String body) {
		if (!PRCommentCommand.mayContainCommand(body)) {
			return false;
		}
		Optional<CommentEvent> parsed = CommentEvent.parse(body);
		if (parsed.isEmpty()) {
			return false;
		}
		CommentEvent event = parsed.get();
		CommentKey key = new CommentKey(pr.getApiLabel(), pr.getRepoName(), pr.getPrId(), event.commentId());
		// Reserve before enqueueing so simultaneous workspace/repository deliveries collapse.
		synchronized (recentComments) {
			long now = clock.getAsLong();
			recentComments.values().removeIf(at -> now - at >= COMMENT_DEDUP_MILLIS);
			if (recentComments.containsKey(key)) {
				duplicateComments.increment();
				return false;
			}
			if (recentComments.size() >= MAX_RECENT_COMMENTS) {
				recentComments.remove(recentComments.keySet().iterator().next());
			}
			PRCommentDeliveryClaims.Claim claim;
			try {
				claim=deliveryClaims==null?null:deliveryClaims.claim(pr.getApiLabel(),pr.getRepoName(),pr.getPrId(),event.commentId());
				if(deliveryClaims!=null&&claim==null){duplicateComments.increment();return false;}
			} catch(RuntimeException e){LOG.warn("Could not reserve a comment delivery; it was not queued");return false;}
			recentComments.put(key, now);
			try {
				executor.execute(() -> handle(pr, event, key, claim));
				return true;
			} catch (RejectedExecutionException e) {
				recentComments.remove(key);
				releaseClaim(claim);
				LOG.warn("Dropped a comment command on pull request {}: too many waiting", pr.getPRString());
				return false;
			}
		}
	}

	private void releaseClaim(PRCommentDeliveryClaims.Claim claim) {
		try {if(deliveryClaims!=null)deliveryClaims.release(claim);}
		catch(RuntimeException e){LOG.warn("Could not release a comment delivery reservation");}
	}

	private void forgetComment(CommentKey key, PRCommentDeliveryClaims.Claim claim) {
		synchronized (recentComments) {
			recentComments.remove(key);
		}
		releaseClaim(claim);
	}

	private void handle(PullRequest pr, CommentEvent event, CommentKey key, PRCommentDeliveryClaims.Claim claim) {
		try {
			Optional<String> reason = PRCommentCommand.bypassReason(event.text());
			if (reason.isEmpty()) {
				return;
			}
			Reply reply = requestBypass(pr, event, reason.get());
			if (!reply.requested() && !refusalAllowed(pr)) {
				LOG.info("Not replying to a repeated bypass command on pull request {}", pr.getPRString());
				return;
			}
			if (!replyTo(pr, event.commentId(), reply.text())) {
				forgetComment(key,claim);
				LOG.warn("Could not reply to the bypass command on pull request {}", pr.getPRString());
			}
		} catch (RuntimeException e) {
			forgetComment(key,claim);
			LOG.warn("Could not handle a comment command on pull request {}", pr.getPRString(), e);
		}
	}

	/**
	 * @return the reply: the request was made, or why not
	 */
	private Reply requestBypass(PullRequest pr, CommentEvent event, String reason) {
		if (reason.isEmpty()) {
			return Reply.refused("⚠️ Add a reason: `" + PRCommentCommand.BYPASS_SYNTAX + "`. Optional category syntax: `" + PRCommentCommand.BYPASS_CATEGORY_SYNTAX + "`");
		}
		PullRequestContainerEntity container = resultService
				.getPullRequestByLabelRepoAndId(pr.getApiLabel(), pr.getRepoName(), pr.getPrId());
		long scanId = container == null || container.getScans() == null ? -1
				: PRScanBypassService.latestScanId(container);
		if (scanId < 0) {
			return Reply.refused(
					"⚠️ Bypass not requested: Watchtower has no scan of this pull request yet.");
		}
		try {
			if(PRCommentCommand.reasonCode(event.text())==BypassReasonCode.OTHER) {
    requestService.request(scanId, event.author(), reason, RequestSource.PR_COMMENT,event.authorId());
   } else {
    requestService.request(scanId,event.author(),reason,RequestSource.PR_COMMENT,event.authorId(),PRCommentCommand.reasonCode(event.text()));
   }
		} catch (PRScanBypassException e) {
			return Reply.refused("⚠️ Bypass not requested: " + e.getMessage());
		}
		String link = PRScanBypassService.reportLink(publicUrl, scanId);
		return new Reply(true, "✅ Bypass requested by " + PRCommentFormat.escape(event.author())
				+ ". An approver has been alerted and will approve or decline it in Watchtower."
				+ (link == null ? "" : " [Open the report](" + link + ")"));
	}

	/**
	 * @return true, and starts the cooldown, unless this pull request got a refusal reply within
	 *         {@link #REFUSAL_COOLDOWN_MILLIS}
	 */
	private boolean refusalAllowed(PullRequest pr) {
		long now = clock.getAsLong();
		if (lastRefusal.size() > MAX_COOLDOWNS) {
			lastRefusal.values().removeIf(at -> now - at >= REFUSAL_COOLDOWN_MILLIS);
		}
		String key = String.join("\u0000", pr.getApiLabel(), pr.getRepoName(), pr.getPrId());
		Long last = lastRefusal.get(key);
		if (last != null && now - last < REFUSAL_COOLDOWN_MILLIS) {
			return false;
		}
		lastRefusal.put(key, now);
		return true;
	}

	/** A reply to a command, and whether a request was made. */
	private record Reply(boolean requested, String text) {
		static Reply refused(String text) {
			return new Reply(false, text);
		}
	}

	/**
	 * @return the name on one line without control characters, so it can't forge log or alert
	 *         lines, cut to fit the requested_by column
	 */
	static String cleanName(String name) {
		String printable = StringUtils.defaultString(name).replaceAll("\\p{Cntrl}", " ");
		return StringUtils.abbreviate(StringUtils.normalizeSpace(printable), MAX_NAME_LENGTH);
	}

	private boolean replyTo(PullRequest pr, long commentId, String text) {
		ApiIntegrationEntity integration = apiService.findByLabel(pr.getApiLabel());
		if (integration == null) {
			return false;
		}
		return ((IScmApi) integration.createApi()).replyToComment(pr, commentId, text);
	}

	@Override
	public void destroy() {
		if (executor instanceof ThreadPoolExecutor pool) {
			pool.shutdownNow();
		}
	}

	/**
	 * The parts of a {@code pullrequest:comment_created} delivery a command needs.
	 */
	record CommentEvent(long commentId, String text, String author, String authorId) {

		static Optional<CommentEvent> parse(String body) {
			try {
				DocumentContext doc = JsonPath.parse(body);
				Number id = doc.read("$.comment.id");
				String text = doc.read("$.comment.content.raw");
				String author = cleanName(doc.read("$.actor.display_name"));
				String authorId = doc.read("$.actor.account_id");
				if (id == null || id.longValue() <= 0 || author.isEmpty()) {
					return Optional.empty();
				}
				return Optional.of(new CommentEvent(id.longValue(), text, author,
						authorId == null ? null : cleanName(authorId)));
			} catch (RuntimeException e) {
				LOG.debug("Not a comment delivery Watchtower can read", e);
				return Optional.empty();
			}
		}
	}
}

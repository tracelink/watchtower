package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A unit of repository scan work on the queue: a scan or a background job, named by its row id.
 * The row holds everything else, so a message is tiny and carries no repository content.
 *
 * @param kind what the id names
 * @param id   the {@code repo_scans} or {@code async_jobs} row id
 * @author Watchtower
 */
public record RepoQueueMessage(Kind kind, long id) {

	public enum Kind {
		SCAN, JOB
	}

	private static final ObjectMapper MAPPER = new ObjectMapper();

	public static RepoQueueMessage scan(long scanId) {
		return new RepoQueueMessage(Kind.SCAN, scanId);
	}

	public static RepoQueueMessage job(long jobId) {
		return new RepoQueueMessage(Kind.JOB, jobId);
	}

	public String toJson() {
		try {
			return MAPPER.writeValueAsString(this);
		} catch (JsonProcessingException e) {
			// two plain fields cannot fail to serialise
			throw new IllegalStateException(e);
		}
	}

	/**
	 * @param body a message body from the queue
	 * @return the message, or empty if the body is not one of ours
	 */
	public static Optional<RepoQueueMessage> fromJson(String body) {
		try {
			RepoQueueMessage message = MAPPER.readValue(body, RepoQueueMessage.class);
			return message.kind() == null || message.id() <= 0 ? Optional.empty()
					: Optional.of(message);
		} catch (JsonProcessingException | IllegalArgumentException e) {
			return Optional.empty();
		}
	}
}

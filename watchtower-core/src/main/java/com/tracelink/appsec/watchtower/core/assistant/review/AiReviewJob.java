package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.function.Consumer;

import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Runs an AI review on the shared job queue; any pod may run it, and a restarted run carries on with the files left. */
@Component
public class AiReviewJob implements AsyncJobHandler {
	private final AiReviewService review;

	public AiReviewJob(AiReviewService review) {
		this.review = review;
	}

	@Override
	public AsyncJobType type() {
		return AsyncJobType.AI_CODE_REVIEW;
	}

	@Override
	public String handle(AsyncJobEntity job, Consumer<String> progress) {
		return review.run(job.getPayload(), progress);
	}
}

/* The pull request results page lists the last 90 days by default (and "Older" on request).
   Without these, every page view sorted and counted every scan ever run: All and "with
   violations" order pull_request_scans by end_date, Unresolved orders unresolved
   pull_request_container rows by last_review_date. Small BIGINT/BOOLEAN keys; built online. */
CREATE INDEX idx_pr_scans_end_date ON pull_request_scans (end_date);

CREATE INDEX idx_pr_container_resolved_reviewed ON pull_request_container (resolved, last_review_date);

-- Bypass requests can now come from a pull request comment, "/watchtower bypass <reason>"
-- (§4.18), as well as from the report page.
--   source: where the request was made, WATCHTOWER (report page) or PR_COMMENT.
--   requester_scm_id: for PR_COMMENT, the commenter's SCM account id (Bitbucket account_id);
--     requested_by then holds their SCM display name, which is not a Watchtower login.
-- Neither column is indexed, so the 3072-byte InnoDB key limit does not apply.
ALTER TABLE pull_request_bypass_requests
  ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'WATCHTOWER';

ALTER TABLE pull_request_bypass_requests
  ADD COLUMN requester_scm_id VARCHAR(64) NULL;

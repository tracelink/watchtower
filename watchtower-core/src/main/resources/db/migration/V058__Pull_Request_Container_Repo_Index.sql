/* Pull requests by repository. Every PR webhook looks its pull request up by
   (api_label, repo_name, pr_id), and the repository page lists a repository's pull requests by
   the first two; the table had only its primary key, so both read the whole table.
   Not unique: older data holds duplicate rows. 3 x VARCHAR(255) utf8mb4 = 3060 bytes, under
   InnoDB's 3072-byte key limit (as idx_pr_bypass_pr in V051). MySQL builds it online. */
CREATE INDEX idx_pr_container_repo ON pull_request_container (api_label, repo_name, pr_id);

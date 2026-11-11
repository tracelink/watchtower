package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestComment;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * An interface for interacting with SCMs in order to work with pull requests, repositories, etc.
 *
 * @author csmith
 */
public interface IScmApi extends IWatchtowerApi {
	/**
	 * The full hash of a commit given by its hash or a short prefix of it. Some systems (Bitbucket Cloud's pull
	 * request objects) hand out truncated hashes, which the pinned reads here refuse. A full hash is returned as it is;
	 * an adapter that cannot complete a short one must fail rather than guess.
	 */
	default String fullCommit(String repository, String commit) throws IOException {
		if (commit != null && commit.matches("[a-fA-F0-9]{40,64}")) {
			return commit;
		}
		throw new IOException("A full pinned commit is required");
	}

	/** Exact pinned merge base; unsupported adapters must fail rather than use moving branches. */
	default String mergeBase(String repository, String head, String base) throws IOException {
		throw new IOException("Pinned merge-base retrieval is unavailable");
	}
	/** Raw unified patch, bounded during transfer. Never reconstruct from parsed line flags. */
	default byte[] rawDiff(String repository, String head, String mergeBase, int maxBytes) throws IOException {
		throw new IOException("Pinned raw diff retrieval is unavailable");
	}

	/**
	 * Ensure that there is a connection to the desired API endpoint(s) using this client
	 *
	 * @param pullRequest the pull request to test connectivity for
	 * @return true if there is a valid connection, false if not
	 */
	boolean testConnectionForPullRequest(PullRequest pullRequest);

	/**
	 * Download the complete source of the current code base under examination
	 *
	 * @param pullRequest     the pull request to download the source of
	 * @param targetDirectory the location to download the complete code
	 * @throws IOException if any streaming/file exceptions occur
	 */
	void downloadSourceForPullRequest(PullRequest pullRequest,
			Path targetDirectory) throws IOException;

	/**
	 * For a given file, calculate the Diff showing the differences between former and new code
	 *
	 * @param pullRequest the pull request to use for diffing
	 * @param filePath    the file to calculate using
	 * @return a DiffFile showing what changes happened on what lines in the file
	 */
	DiffFile getGitDiffFile(PullRequest pullRequest, String filePath);

	/**
	 * Fetches a single file's full raw content, on the pull request's source branch, for inline
	 * display on the PR scan report page. Unlike {@link #getGitDiffFile(PullRequest, String)}
	 * (which deliberately discards line text, keeping only modified/existing line numbers for
	 * scan classification) or {@link #downloadFileAtCommit(PullRequest, String, Path)} (which
	 * requires the scan-time commit hash, not persisted after the scan completes), this reads
	 * the branch's current state and returns it in memory rather than writing to disk.
	 *
	 * @param pullRequest the pull request whose source branch to read the file from
	 * @param filePath    the path, relative to the repository root, of the file to fetch
	 * @return the file's content, or null if it could not be fetched (not found, deleted since
	 *         the scan ran, rate-limited past the retry budget, etc.)
	 */
	String getFileContent(PullRequest pullRequest, String filePath);

	/**
	 * Returns every file changed in this pull request, each mapped to the {@linkplain DiffFile}
	 * describing the changes made to it. Fetches all changed files in a single call, unlike
	 * {@link #getGitDiffFile(PullRequest, String)} which fetches one file at a time.
	 *
	 * @param pullRequest the pull request to fetch changed files for
	 * @return a map of file path to {@link DiffFile}, one entry per changed file; empty (never
	 *         null) if the pull request has no changes or the diff could not be fetched
	 */
	Map<String, DiffFile> getChangedFilesForPullRequest(PullRequest pullRequest);

	/**
	 * Downloads the content of a single file at the pull request's commit hash into the target
	 * directory, preserving its relative path (a file at {@code src/main/Foo.java} lands at
	 * {@code targetDirectory/src/main/Foo.java}).
	 * <p>
	 * Used so {@code CHANGED_FILES} and {@code MANIFEST_FILES} scoped scanners can fetch
	 * individual files without downloading the full repository.
	 *
	 * @param pullRequest     the pull request to fetch the file at
	 * @param filePath        the path, relative to the repository root, of the file to fetch
	 * @param targetDirectory the working directory to write the file into
	 * @throws IOException if {@code filePath} resolves outside {@code targetDirectory}, or the
	 *                      file could not be written
	 */
	void downloadFileAtCommit(PullRequest pullRequest, String filePath, Path targetDirectory)
			throws IOException;

	/**
	 * Lists every file path present in the repository at the pull request's commit hash,
	 * without downloading any file content (IMPROVEMENT_PLAN.md item 2.5b). Used so
	 * {@code MANIFEST_FILES}-scoped scanners can resolve which files match their glob
	 * patterns against a real directory listing, instead of guessing at paths - a wrong
	 * guess risks silently missing a file a scanner needs.
	 *
	 * @param pullRequest the pull request whose commit to list files at
	 * @return every file path in the repository at that commit, relative to the
	 *         repository root; empty (never null) if the listing could not be fetched,
	 *         matching {@link #getChangedFilesForPullRequest(PullRequest)}'s convention
	 */
	List<String> listFilesAtCommit(PullRequest pullRequest);

	/**
	 * This method is used to complete or update all data in a pull request in the event that only
	 * partial data was transmitted or captured
	 *
	 * @param pullRequest the known pull request data to use to update
	 * @return a new pull request object with all data filled
	 * @throws ScanRejectedException if this client is unable to completely fill the PullRequest
	 */
	PullRequest updatePRData(PullRequest pullRequest) throws ScanRejectedException;

	/**
	 * Notifies pull request of result/status of the report. Implementation is SCM specific
	 *
	 * @param pullRequest the pull request to send the comment to
	 * @param comment     the formatted comment content
	 * @return false if sending was attempted and failed; true if it succeeded or the integration
	 *         is configured not to comment
	 */
	boolean sendComment(PullRequest pullRequest, String comment);

	/**
	 * Lists the pull request's comments that are not deleted, PR-level and inline.
	 *
	 * @param pullRequest the pull request
	 * @return its comments; empty if the integration is configured not to comment; null if they
	 *         could not be read
	 */
	List<PullRequestComment> listComments(PullRequest pullRequest);

	/**
	 * Comments on one line of a file in the pull request's diff.
	 *
	 * @param pullRequest the pull request
	 * @param path        the repo-relative file
	 * @param line        the line in the new version of the file; it must be part of the diff
	 * @param comment     the formatted comment content
	 * @return false if sending was attempted and failed; true if it succeeded or the integration
	 *         is configured not to comment
	 */
	boolean sendInlineComment(PullRequest pullRequest, String path, int line, String comment);

	/**
	 * @return true if a pull request Watchtower blocks stays open, so its developer can still ask
	 *         for a bypass on it; false if blocking declines it
	 */
	default boolean keepsBlockedPullRequestsOpen() {
		return true;
	}

	/**
	 * Replies to a comment, in its thread.
	 *
	 * @param pullRequest the pull request
	 * @param commentId   the comment to reply to
	 * @param comment     the formatted reply
	 * @return false if sending was attempted and failed; true if it succeeded or the integration
	 *         is configured not to comment
	 */
	boolean replyToComment(PullRequest pullRequest, long commentId, String comment);

	/**
	 * Replaces the text of a comment the integration account wrote.
	 *
	 * @param pullRequest the pull request
	 * @param commentId   the comment
	 * @param comment     the new content
	 * @return false if the edit was attempted and failed; true if it succeeded or the integration
	 *         is configured not to comment
	 */
	boolean updateComment(PullRequest pullRequest, long commentId, String comment);

	/**
	 * Deletes a comment the integration account wrote.
	 *
	 * @param pullRequest the pull request
	 * @param commentId   the comment
	 * @return false if the delete was attempted and failed; true if it succeeded or the
	 *         integration is configured not to comment
	 */
	boolean deleteComment(PullRequest pullRequest, long commentId);

	/**
	 * Sends signal to SCM to block the pull request Implementation is SCM specific
	 *
	 * @param pullRequest the pull request to block
	 * @return false if blocking was attempted and failed; true if it succeeded or the
	 *         integration is configured not to block
	 */
	boolean blockPR(PullRequest pullRequest);

	/**
	 * Approve the pull request as the integration account, first withdrawing any earlier "request
	 * changes" from that account. Implementations only act when the integration is configured to
	 * manage review state; otherwise this is a no-op.
	 *
	 * @param pullRequest the pull request to approve
	 * @return false if the review state could not be set as intended (including when the head
	 *         commit could not be confirmed); true if it was set or deliberately left alone
	 */
	boolean approvePR(PullRequest pullRequest);

	/**
	 * Request changes on the pull request as the integration account, first withdrawing any
	 * earlier approval from that account. Implementations only act when the integration is
	 * configured to manage review state; otherwise this is a no-op.
	 *
	 * @param pullRequest the pull request to request changes on
	 * @return false if the review state could not be set as intended (including when the head
	 *         commit could not be confirmed); true if it was set or deliberately left alone
	 */
	boolean requestChangesPR(PullRequest pullRequest);

	/**
	 * For a given repository, get all currently open pull requests
	 *
	 * @param repoName the repository name to search for open pull requests
	 * @return a list of open pull requests
	 */
	List<PullRequest> getOpenPullRequestsForRepository(String repoName);

	/**
	 * For a given repository, test if the repository is still active in the SCM
	 *
	 * @param repoName the repository name to check
	 * @return false only if the SCM says the repository does not exist; true if it does, or if
	 *         the SCM could not tell (an auth error, an outage)
	 */
	boolean isRepositoryActive(String repoName);

	/**
	 * Lists every repository the integration can see, one page at a time, so a caller can
	 * persist each page as it arrives instead of holding the whole listing.
	 *
	 * @param pageConsumer receives each page of repositories, in listing order
	 * @return true only if every page was listed; false if the listing stopped early (a
	 *         failed or rate-limited page), in which case the pages already delivered are
	 *         an incomplete view and must not be used to decide that a repository is gone
	 */
	boolean listRepositories(Consumer<List<ScmRepository>> pageConsumer);

	/**
	 * Reads one repository, as {@link #listRepositories(Consumer)} lists it. Used to add a
	 * repository to the catalog by hand.
	 *
	 * @param repoName the repository's slug, already checked to be a plain name
	 * @return the repository, or empty if the SCM does not know it or it could not be read
	 */
	Optional<ScmRepository> getRepository(String repoName);

	/**
	 * Lists a repository's branches, most recently committed first.
	 *
	 * @param repoName   the repository name
	 * @param nameFilter a substring the branch name must contain, or blank for all branches
	 * @param limit      the most branches to return
	 * @return the branches found, empty (never null) if they could not be listed
	 */
	List<ScmBranch> listBranches(String repoName, String nameFilter, int limit);

	/**
	 * @param repoName   the repository name
	 * @param branchName the branch name
	 * @return the branch and its head commit, or empty if the branch does not exist or could
	 *         not be read
	 */
	Optional<ScmBranch> getBranch(String repoName, String branchName);

	/**
	 * Downloads the complete source of a repository at a commit into a directory.
	 *
	 * @param repoName        the repository name
	 * @param commitHash      the commit to download
	 * @param targetDirectory the directory the repository root becomes
	 * @throws IOException if the download or extraction fails
	 */
	void downloadSource(String repoName, String commitHash, Path targetDirectory)
			throws IOException;

	/** Bounded download capability; adapters must enforce limits before accepting source tools. */
	default void downloadSource(String repoName, String commitHash, Path targetDirectory,
			SourceDownloadLimits limits) throws IOException {
		throw new IOException("Bounded pinned source download is unavailable for this integration");
	}

	/**
	 * Fetches a single file's raw content at a commit, in memory only. Used to show a few
	 * lines around a finding when a report is viewed, so no source is ever stored.
	 *
	 * @param repoName   the repository name
	 * @param commitHash the commit to read the file at
	 * @param filePath   the path, relative to the repository root
	 * @return the file's content, or null if it could not be fetched
	 */
	String getFileContentAtCommit(String repoName, String commitHash, String filePath);

	/**
	 * Like {@link #getFileContentAtCommit}, but says why when the file could not be read. The
	 * default cannot tell, so an integration that can (from its server's answer) overrides it.
	 *
	 * @param repoName   the repository name
	 * @param commitHash the commit to read the file at
	 * @param filePath   the path, relative to the repository root
	 * @return the content, or the reason there is none; never null
	 */
	default FileFetch fetchFileAtCommit(String repoName, String commitHash, String filePath) {
		String content = getFileContentAtCommit(repoName, commitHash, filePath);
		return content != null ? FileFetch.found(content) : FileFetch.unavailable(null);
	}

	/** Bounded, exact bytes for provider source-proof verification; no unbounded fallback. */
	default byte[] boundedFileAtCommit(String repository, String commit, String file, int maxBytes) throws IOException {
		throw new IOException("Bounded pinned source retrieval unavailable");
	}

	/**
	 * Downloads a single file at a commit into a directory, preserving its relative path.
	 *
	 * @param repoName        the repository name
	 * @param commitHash      the commit to fetch the file at
	 * @param filePath        the path, relative to the repository root
	 * @param targetDirectory the directory to write the file into
	 * @throws IOException if {@code filePath} resolves outside {@code targetDirectory}, or the
	 *                      file could not be written
	 */
	void downloadFileAtCommit(String repoName, String commitHash, String filePath,
			Path targetDirectory) throws IOException;
}

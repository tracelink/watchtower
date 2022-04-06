package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;

/**
 * An interface for interacting with SCMs in order to work with pull requests, repositories, etc.
 * 
 * @author csmith
 *
 */
public interface IScmApi extends IWatchtowerApi {

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
	 */
	void sendComment(PullRequest pullRequest, String comment);

	/**
	 * Sends signal to SCM to block the pull request Implementation is SCM specific
	 * 
	 * @param pullRequest the pull request to block
	 */
	void blockPR(PullRequest pullRequest);

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
	 * @return true if the repo still exists in the SCM, false otherwise
	 */
	boolean isRepositoryActive(String repoName);
}

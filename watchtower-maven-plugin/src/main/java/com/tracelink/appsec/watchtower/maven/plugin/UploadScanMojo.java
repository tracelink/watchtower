package com.tracelink.appsec.watchtower.maven.plugin;

import com.tracelink.appsec.watchtower.cli.executor.UploadScanExecutor;
import com.tracelink.appsec.watchtower.cli.executor.UploadScanParameters;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/**
 * Mojo to perform a Watchtower upload scan via the {@link UploadScanExecutor} as part of the Maven
 * lifecycle.
 *
 * @author mcool
 */
@Mojo(name = "watchtower-upload-scan", defaultPhase = LifecyclePhase.COMPILE)
public class UploadScanMojo extends AbstractMojo {

	@Parameter(defaultValue = "${project}", required = true, readonly = true)
	private MavenProject project;

	@Parameter(required = true)
	private String watchtowerUrl;

	@Parameter(defaultValue = "${watchtowerApiKeyId}", required = true, readonly = true)
	private String watchtowerApiKeyId;

	@Parameter(defaultValue = "${watchtowerApiSecret}", required = true, readonly = true)
	private String watchtowerApiSecret;

	@Parameter()
	private String target;

	@Parameter()
	private String output;

	@Parameter()
	private String fileName;

	@Parameter()
	private String ruleset;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		try {
			UploadScanParameters params = new UploadScanParameters();
			params.setServerUrl(watchtowerUrl);
			params.setApiKeyId(watchtowerApiKeyId);
			params.setApiSecret(watchtowerApiSecret);
			if (StringUtils.isBlank(target)) {
				params.setTarget(project.getBasedir().getAbsolutePath());
			} else {
				params.setTarget(target);
			}
			params.setOutput(output);
			params.setFileName(fileName);
			params.setRuleset(ruleset);

			UploadScanExecutor executor = new UploadScanExecutor(params);
			executor.executeUploadScan();
		} catch (Exception e) {
			throw new MojoExecutionException(
					"An exception occurred while performing Watchtower upload scan", e);
		}
	}
}

package com.tracelink.appsec.watchtower.cli.executor;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class to hold parameters for a Watchtower upload scan. Validates the CLI arguments.
 *
 * @author mcool
 */
public class UploadScanParameters {

	private static final Logger LOG = LoggerFactory.getLogger(UploadScanParameters.class);
	private static final String CMD_LINE_SYNTAX = "java -jar watchtower-cli.jar -u watchtowerUrl -k apiKeyId -s apiSecret -t target [-o output] [-n fileName] [-r ruleset]";
	private final Options options;

	private String serverUrl;
	private String apiKeyId;
	private String apiSecret;
	private String target;
	private String output;
	private String fileName;
	private String ruleset;

	public UploadScanParameters() {
		Option urlOption = Option.builder("u")
				.required()
				.desc("Watchtower server URL")
				.longOpt("url")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option apiKeyOption = Option.builder("k")
				.required()
				.desc("Watchtower API key ID")
				.longOpt("apiKey")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option apiSecretOption = Option.builder("s")
				.required()
				.desc("Watchtower API secret")
				.longOpt("apiSecret")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option targetOption = Option.builder("t")
				.required()
				.desc("Target directory or file to upload and scan")
				.longOpt("target")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option outputOption = Option.builder("o")
				.required(false)
				.desc("CSV output file for scan results (results will be logged to console as text if not specified)")
				.longOpt("output")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option fileNameOption = Option.builder("n")
				.required(false)
				.desc("Name for the zip file to upload to Watchtower (defaults to target folder/file name if not specified)")
				.longOpt("fileName")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option rulesetOption = Option.builder("r")
				.required(false)
				.desc("Name of the ruleset to apply during the Watchtower scan (uses default ruleset if not specified")
				.longOpt("ruleset")
				.hasArg()
				.numberOfArgs(1)
				.build();

		options = new Options();
		options.addOption(urlOption);
		options.addOption(apiKeyOption);
		options.addOption(apiSecretOption);
		options.addOption(targetOption);
		options.addOption(outputOption);
		options.addOption(fileNameOption);
		options.addOption(rulesetOption);
	}

	/**
	 * Parses the given CLI arguments for a Watchtower upload scan. Logs a help message if the
	 * arguments are invalid.
	 *
	 * @param args the arguments to parse and store
	 * @return true if the arguments are valid, false otherwise
	 */
	public boolean parseArgs(String[] args) {
		CommandLineParser parser = new DefaultParser();
		CommandLine commandLine;
		try {
			commandLine = parser.parse(options, args);
			// Set command line option values
			serverUrl = commandLine.getOptionValue("u");
			apiKeyId = commandLine.getOptionValue("k");
			apiSecret = commandLine.getOptionValue("s");
			target = commandLine.getOptionValue("t");
			output = commandLine.getOptionValue("o");
			fileName = commandLine.getOptionValue("n");
			ruleset = commandLine.getOptionValue("r");
		} catch (Exception e) {
			LOG.error("Exception occurred while parsing arguments. " + e.getMessage());
			new HelpFormatter().printHelp(CMD_LINE_SYNTAX, options);
			return false;
		}
		return true;
	}

	public String getServerUrl() {
		return serverUrl;
	}

	public void setServerUrl(String serverUrl) {
		this.serverUrl = serverUrl;
	}

	public String getApiKeyId() {
		return apiKeyId;
	}

	public void setApiKeyId(String apiKeyId) {
		this.apiKeyId = apiKeyId;
	}

	public String getApiSecret() {
		return apiSecret;
	}

	public void setApiSecret(String apiSecret) {
		this.apiSecret = apiSecret;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getOutput() {
		return output;
	}

	public void setOutput(String output) {
		this.output = output;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getRuleset() {
		return ruleset;
	}

	public void setRuleset(String ruleset) {
		this.ruleset = ruleset;
	}
}

package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Reads a Watchtower command from a pull request comment (§4.18). The only command is
 * {@code /watchtower bypass <reason>}, which asks for a bypass the same way "Request bypass" on
 * the report does. It must start the comment, so quoting it inside a sentence does nothing.
 *
 * @author Watchtower
 */
public final class PRCommentCommand {

	/** The command as developers type it; also used in Watchtower's own hints. */
	public static final String BYPASS_SYNTAX = "/watchtower bypass <reason>";
 public static final String BYPASS_CATEGORY_SYNTAX = "/watchtower bypass [fp|risk|test|unexploitable] <reason>";

	private static final String PREFIX = "/watchtower";

	/**
	 * The command may be wrapped in backticks (groups 1 and 2): Bitbucket stores a pasted or
	 * formatted command that way, and the bot's own hint shows it as code.
	 */
	private static final Pattern BYPASS = Pattern.compile(
			"\\A\\s*(`*)/watchtower[ \\t]+bypass(`*)(?:[ \\t]+|\\R|\\z)(.*)\\z",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

	private PRCommentCommand() {
	}

	/**
	 * @param comment a comment's raw text
	 * @return the reason (empty if none was given) when the comment is a bypass command, or empty
	 *         when it is not a command
	 */
	public static Optional<String> bypassReason(String comment) {
		if (comment == null) {
			return Optional.empty();
		}
		Matcher matcher = BYPASS.matcher(comment);
		return matcher.matches() ? Optional.of(parsed(reasonText(matcher)).reason())
				: Optional.empty();
	}

	/**
	 * The text after the command. When the whole line was wrapped, "`/watchtower bypass why`", the
	 * closing backtick ends the reason and is dropped; a reason's own backticks are kept.
	 */
	private static String reasonText(Matcher matcher) {
		String text = StringUtils.strip(matcher.group(3));
		boolean wholeLineWrapped = !matcher.group(1).isEmpty() && matcher.group(2).isEmpty();
		return wholeLineWrapped ? StringUtils.stripEnd(text, "`").stripTrailing() : text;
	}

 public record Reason(BypassReasonCode code,String reason) { }
 public static Reason parsed(String value) {
  String[] parts=value.split("\\s+",2);
  BypassReasonCode code=switch(parts[0]) {
   case "fp" -> BypassReasonCode.FALSE_POSITIVE;case "risk" -> BypassReasonCode.ACCEPTED_RISK;
   case "test" -> BypassReasonCode.TEST_CODE;case "unexploitable" -> BypassReasonCode.NOT_EXPLOITABLE;default -> BypassReasonCode.OTHER;
  };
  return code==BypassReasonCode.OTHER?new Reason(code,value):new Reason(code,parts.length==2?parts[1]:"");
 }
 public static BypassReasonCode reasonCode(String comment) {
  Matcher m=BYPASS.matcher(comment==null?"":comment);return m.matches()?parsed(reasonText(m)).code():BypassReasonCode.OTHER;
 }

	/**
	 * A cheap check on a webhook body before it is parsed: most comments are not commands, and
	 * they should cost nothing more than this.
	 *
	 * @param body a raw webhook body
	 * @return false if the body cannot contain a command
	 */
	public static boolean mayContainCommand(String body) {
		return body != null && body.toLowerCase(Locale.ROOT).contains(PREFIX);
	}
}

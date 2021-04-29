package com.tracelink.appsec.watchtower.core.module.interpreter;

import java.io.IOException;
import java.io.InputStream;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Object that can interpret rules stored in various formats. This class is used to convert rules
 * from a file format, such as XML or JSON, to the database storage format and vice versa. It is
 * also used during scans to convert database rules into temporary files.
 *
 * @author mcool
 */
public interface IRulesetInterpreter {

	/**
	 * Import the ruleset contained in the given InputStream to a {@linkplain RulesetDto} format.
	 * This allows the rules in the ruleset to be validated before they are stored in the database.
	 * It is the responsibility of this method to close the input stream.
	 *
	 * @param inputStream stream of file containing the ruleset to be imported
	 * @return ruleset DTO object representing the ruleset in the stream, never null
	 * @throws IOException                 if an error occurs reading data from the stream
	 * @throws RulesetInterpreterException if the ruleset is invalid or incorrectly formatted
	 */
	RulesetDto importRuleset(InputStream inputStream)
			throws IOException, RulesetInterpreterException;

	/**
	 * Export the given {@link RulesetDto} to a stream representing the content of the ruleset. This
	 * content will be added to a zip file in the case of ruleset export, but will also be written
	 * to a local file for scanning. Returns null if there are no rules in the ruleset that the
	 * interpreter knows how to export.
	 *
	 * @param rulesetDto ruleset DTO object to export
	 * @return stream containing representation of the given ruleset, or null if there are no rules
	 *         to interpret
	 * @throws IOException                 if an error occurs while creating the stream
	 * @throws RulesetInterpreterException if the ruleset cannot be exported
	 */
	InputStream exportRuleset(RulesetDto rulesetDto)
			throws IOException, RulesetInterpreterException;

	/**
	 * Export a "Model" ruleset to a stream. This model is used to provide users with an
	 * understanding of what data can be provided and in what format during import
	 * 
	 * @return stream containing the representation of the import model.
	 * @throws IOException                 if an error occurs while creating the stream
	 * @throws RulesetInterpreterException if the ruleset cannot be exported
	 */
	InputStream exportExampleRuleset() throws IOException, RulesetInterpreterException;

	/**
	 * The file extension for the content of the stream that is exported. This is used during
	 * ruleset export to correctly name each entry in the zip file.
	 * <p>
	 * e.g. "xml" or "json"
	 *
	 * @return file extension of the export stream content
	 */
	String getExtension();
}

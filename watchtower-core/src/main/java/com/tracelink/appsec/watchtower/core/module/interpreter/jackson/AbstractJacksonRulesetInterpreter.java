package com.tracelink.appsec.watchtower.core.module.interpreter.jackson;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Abstract implementation of an {@link IRulesetInterpreter} for rulesets that are represented as
 * XML. Provides abstracted logic to import and export from an XML format.
 *
 * @author mcool
 */
public abstract class AbstractJacksonRulesetInterpreter implements IRulesetInterpreter {
	private RulesetDto exampleRuleset;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final RulesetDto importRuleset(InputStream inputStream)
			throws IOException, RulesetInterpreterException {
		AbstractRulesetImpexModel impexModel;
		ObjectMapper mapper = getObjectMapper();

		impexModel = mapper.readValue(inputStream, getRulesetModelClass());
		inputStream.close();
		RulesetDto ruleset = importInternal(impexModel);
		if (ruleset.isProvided()) {
			throw new RulesetInterpreterException(
					"Cannot import a Provided ruleset. These rules are automatically included in Watchtower");
		}
		return ruleset;
	}

	/**
	 * Internal import function to map the transformed {@linkplain AbstractRuleImpexModel} to the
	 * final {@linkplain RulesetDto}. This method is expected to be overrided if needed.
	 * 
	 * @param impexModel the translated model
	 * @return the final ruleset
	 * @throws RulesetInterpreterException if anything goes wrong during this translation
	 */
	protected RulesetDto importInternal(AbstractRulesetImpexModel impexModel)
			throws RulesetInterpreterException {
		RulesetDto dto = new RulesetDto();
		dto.setName(impexModel.getName());
		dto.setDescription(impexModel.getDescription());
		dto.setRules(impexModel.getRules().stream().map(AbstractRuleImpexModel::toDto)
				.collect(Collectors.toSet()));
		return dto;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws RulesetInterpreterException
	 */
	@Override
	public final InputStream exportRuleset(RulesetDto rulesetDto)
			throws IOException, RulesetInterpreterException {
		if (rulesetDto == null) {
			return null;
		}
		if (rulesetDto.isProvided()) {
			throw new RulesetInterpreterException(
					"Cannot export a Provided ruleset. These rules are automatically included in Watchtower");
		}
		AbstractRulesetImpexModel impexModel = fromDto(rulesetDto);
		if (impexModel == null) {
			return null;
		}
		ObjectMapper mapper = getObjectMapper();
		return new ByteArrayInputStream(mapper.writeValueAsString(impexModel).getBytes());
	}

	@Override
	public InputStream exportExampleRuleset() throws IOException, RulesetInterpreterException {
		if (exampleRuleset == null) {
			exampleRuleset = makeExampleRuleset();
		}
		return exportRuleset(exampleRuleset);
	}

	/**
	 * Create an ObjectMapper instance that can serialize/deserialize the ruleset data to the
	 * ruleset object
	 * 
	 * @return a configured ObjectMapper for this data encoding
	 */
	protected abstract ObjectMapper getObjectMapper();

	/**
	 * The class of the ruleset XML model. This is used to import rulesets and deserialize from XML.
	 *
	 * @return the class of the ruleset XML model
	 */
	protected abstract Class<? extends AbstractRulesetImpexModel> getRulesetModelClass();

	/**
	 * Converts from the given ruleset DTO object to an {@link AbstractRulesetImpexModel} that can
	 * be serialized into XML content. Returns null if there are no rules in the ruleset DTO that
	 * can be interpreted by this interpreter.
	 *
	 * @param rulesetDto ruleset DTO to convert to an XML model
	 * @return XML model representing the given ruleset DTO
	 */
	protected abstract AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto);

	/**
	 * Create an example ruleset to be exported as part of providing a model XML to users wishing to
	 * do a custom import
	 * 
	 * @return a Ruleset showcasing the different cases this interpreter supports during import
	 */
	protected abstract RulesetDto makeExampleRuleset();
}

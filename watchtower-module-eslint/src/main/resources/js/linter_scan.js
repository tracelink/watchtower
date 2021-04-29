const Linter = require("eslint").Linter;

module.exports = {
	scanCode
}

/**
 * Scans the given code using the ruleset at the provided path. Returns a list of Linter messages
 * containing errors that occurred or rule violations.
 */
function scanCode(code, directory, file, rulesetPath) {
	const linter = new Linter({ cwd: directory });

	// Require ruleset and define rules in the Linter
	const ruleset = require(rulesetPath).ruleset;
	const customRules = ruleset.customRules;
	linter.defineRules(ruleset.customRules);
	// Create rules configuration
	const config = {};
	Object.keys(ruleset.priorities).forEach((key) => {
		config[key] = 1;
	});

	// Call verify to check code for issues
	const results = linter.verify(code, { parserOptions: { ecmaVersion: 2020 }, rules: config },
			{ filename: file });
  	return JSON.stringify(results);
}


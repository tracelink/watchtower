const Linter = require("eslint").Linter;
const estraverse = require("estraverse");

module.exports = {
	getCoreRules,
	parseAst,
	parseRuleset
}

/**
 * Gets information about the core rules built-in to the Linter.
 */
function getCoreRules() {
	const linter = new Linter();
	const rulesMap = linter.getRules();
	const rules = {};
	rulesMap.forEach((value, key, map) => {
		let description = value["meta"]["docs"]["description"];
		let url = value["meta"]["docs"]["url"];
		rules[key] = {
			description: description,
			url: url
		}
	});
	return JSON.stringify(rules);
}

/**
 * Parses the given JavaScript code and returns an abstract syntax tree. If the code is invalid,
 * returns parsing errors.
 */
function parseAst(code) {
	const linter = new Linter();
    // Verify code with no rules in order to generate AST
    const results = linter.verify(code, { parserOptions: { ecmaVersion: 2020 }, rules: {}});
    // If there are errors, return
    if (results.length > 0) {
    	return results;
    }
    // Return the AST
    const ast = linter.getSourceCode().ast;
	return JSON.stringify(ast, getCircularReplacer());
}

/**
 * Replaces circular references in the AST so it can be formatted as JSON.
 */
const getCircularReplacer = () => {
  const seen = [];
  return (key, value) => {
    if (typeof value === "object" && value !== null) {
      if (seen.includes(value)) {
        return;
      }
      seen.push(value);
    }
    return value;
  };
};

/**
 * Parses the given JavaScript code into a JSON ruleset object that can be parsed in Java.
 */
function parseRuleset(code) {
	const linter = new Linter();
	// Verify code with no rules in order to generate AST
	const results = linter.verify(code, { parserOptions: { ecmaVersion: 2020 }, rules: {}});
	// If there are errors, return
	if (results.length > 0) {
		return results;
	}
	var rulesetRange;
	var createFunctionRanges = [];
	// Traverse the AST
	const ast = linter.getSourceCode().ast;
	estraverse.traverse(ast, {
		enter: function(node, parent) {
			if (isAssignmentExpression(node)) {
				// We have found module.exports
				if (isModuleExports(node.left)) {
					// We have found the ruleset object
					if (isRulesetObject(node.right)) {
                      	// Keep track of the ruleset object range
                      	rulesetRange = node.right.properties[0].value.range;
                      	// Search the ruleset fields to find the custom rules
    					node.right.properties[0].value.properties.forEach((rulesetField) => {
    						// We have found the custom rules
    						if (isCustomRulesMap(rulesetField)) {
    							rulesetField.value.properties.forEach((ruleEntry) => {
                                	if (isRuleDefinition(ruleEntry)) {
                                		// Search the rule fields to find the create function
                                		ruleEntry.value.properties.forEach((ruleField) => {
                                			// We have found the create function
                                			if (isCreateFunction(ruleField)) {
                                				// Keep track of the range of each create function
                                				createFunctionRanges.push(ruleField.range);
                                			}
                                		});
                                	}
                                });
    						}
    					});
    				}
    			}
    		}
    	}
    });
    return getJsonRuleset(code, rulesetRange, createFunctionRanges);
}

/**
 * Helper function to transform the JavaScript ruleset into a proper JSON object.
 */
function getJsonRuleset(code, rulesetRange, createFunctionRanges) {
	// If there is no ruleset object, return null
	if (rulesetRange === null || rulesetRange === undefined) {
		return [{
			message: "Please provide a Javascript file whose module.exports contains a single ruleset object",
			severity: 2,
			fatal: true
		}];
	}
	var result = "";
	var chunkStart = rulesetRange[0];
	// Convert each create function into a field of the rule
	createFunctionRanges.forEach((range) => {
		result = result.concat(code.substring(chunkStart, range[0]),
				"createFunction: ",
				JSON.stringify(code.substring(range[0], range[1])));
		chunkStart = range[1];
	});
	result = result.concat(code.substring(chunkStart, rulesetRange[1]));
	return result;
}

/**
 * Helper functions to simplify AST logic and prevent errors.
 */

function isAssignmentExpression(node) {
	return node.type === "AssignmentExpression" && node.operator === "=";
}

function isModuleExports(node) {
	return node.type === "MemberExpression" && node.object.name === "module"
			&& node.property.name === "exports";
}

function isRulesetObject(node) {
	return node.properties.length === 1 && node.properties[0].key.type === "Identifier"
			&& node.properties[0].key.name === "ruleset"
			&& node.properties[0].value.type === "ObjectExpression";
}

function isCustomRulesMap(node) {
	return node.key.type === "Identifier" && node.key.name === "customRules"
			&& node.value.type === "ObjectExpression";
}

function isRuleDefinition(node) {
	return node.key.type === "Literal" && node.value.type === "ObjectExpression";
}

function isCreateFunction(node) {
	return node.key.type === "Identifier" && node.key.name === "create"
			&& node.value.type === "FunctionExpression" && node.value.params.length === 1;
}

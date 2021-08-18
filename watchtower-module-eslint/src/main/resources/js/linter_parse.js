const Linter = require("eslint").Linter;

module.exports = {
	getCoreRules,
	getCoreCategories,
	parseAst
}

/**
 * Gets information about the core rules built-in to the Linter.
 */
function getCoreRules() {
	const linter = new Linter();
	const rulesMap = linter.getRules();
	const rules = [];
	rulesMap.forEach((value, key, map) => {
		let description = value["meta"]["docs"]["description"];
		let url = value["meta"]["docs"]["url"];
		let category = value["meta"]["docs"]["category"];
		rules.push({
			name: key,
			description: description,
			url: url,
			category: category
		});
	});
	return JSON.stringify(rules);
}

function getCoreCategories(){
	const path = require('path');
	const fs = require('fs');
	const config = path.resolve(require.resolve('eslint'),'../../conf/category-list.json');
	let raw = fs.readFileSync(config);
	let categoriesList = JSON.parse(raw)['categories'];
	return categoriesList;
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


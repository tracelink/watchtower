# Watchtower Module: ESLint

This module integrates with
the [ESLint Linter](https://eslint.org/docs/developer-guide/nodejs-api#linter) to scan JavaScript
files for common issues. There are many [rules](https://eslint.org/docs/rules/) built-in to ESLint
that can be easily configured as core rules within Watchtower. Additionally, custom ESLint rules can
be designed using the Watchtower UI or imported as a JS file.

This ESLint Module expects nodejs 12+ to be installed along with npm in the operating environment using the 'node' and 'npm' binaries, respectively. This module will install the correct version of ESLint and Estraverse in order to operate correctly. The module will attempt to correct any node version conflicts of these projects if any inconsistencies are found in the environment.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [Module Name](#module-name)
- [Database Schema History Table](#database-schema-history-table)
- [Database Migrations Location](#database-migrations-location)
- [Additional Rule Fields](#additional-rule-fields)

## Module Name

ESLint

## Database Schema History Table

`eslint_schema_history`

## Database Migrations Location

`db/eslint`

## Additional Rule Fields

| Field | Description | Example | 
|--------|------------|---------|
| core | Boolean indicating whether or not this is a core rule | `true` for core rules; `false` for custom rules |
| createFunction | JS code (as a string) for the "create" function of the rule. Only required for custom rules. | See [Working with Rules](https://eslint.org/docs/developer-guide/working-with-rules) for more info. |
| messages | List of message IDs and values that are referenced in the "create" function of the rule. Only required for custom rules. | See [Working with Rules](https://eslint.org/docs/developer-guide/working-with-rules) for more info. |
| The remaining fields are not used by Watchtower but can be provided on rule import for compatibility. |||
| ruleType | The type of ESLint rule | One of `"problem"`, `"suggestion"`, or `"layout"` |
| category | The category the ESLint rule falls into | See [Rules Index](https://eslint.org/docs/rules/) for categories. | 
| recommended | Boolean indicating whether the `"extends": "eslint:recommended"` property in a configuration file enables the rule | `true` if the rule is recommended; `false` otherwise |
| suggestion | Boolean indicating whether the rule can return suggestions | `true` if the rule can return suggestions, `false` otherwise |
| fixable | Boolean indicating whether the rule can be automatically fixed using the `--fix` option on the ESLint command line | `true` if the rule is fixable, `false` otherwise  |
| schema | An array specifying rule schema options so ESLint can prevent invalid rule configurations | See [Working with Rules](https://eslint.org/docs/developer-guide/working-with-rules) for more info. |
| deprecated | Boolean indicating whether the rule is deprecated | `true` if the rule is deprecated; `false` otherwise |
| replacedBy | Name of another rule replacing the rule, if the rule is deprecated | `"some-other-rule"` |

Note that the name of a core ESLint rule in Watchtower must match the name of the built-in ESLint
rule.

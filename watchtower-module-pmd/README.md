# Watchtower Module: PMD

This module integrates with the [PMD](https://pmd.github.io/) static code analyzer.
PMD [XPath rules](https://pmd.github.io/pmd-6.32.0/pmd_userdocs_extending_writing_xpath_rules.html)
can be designed and imported into Watchtower to scan Java, Ecmascript, Scala, and XML files.

Watchtower has limited support for
PMD [Java rules](https://pmd.github.io/pmd-6.32.0/pmd_userdocs_extending_writing_java_rules.html).
If you would like to add a Java rule, add the Java code as a file to the PMD Module's resources
folder, then deploy Watchtower and create a rule that references the Java file.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [Module Name](#module-name)
- [Database Schema History Table](#database-schema-history-table)
- [Database Migrations Location](#database-migrations-location)
- [Additional Rule Fields](#additional-rule-fields)

## Module Name

PMD

## Database Schema History Table

`pmd_schema_history`

## Database Migrations Location

`db/pmd`

## Additional Rule Fields

| Field | Description | Example | 
|--------|------------|---------|
| parserLanguage | Language the rule is associated with | `"java"` |
| ruleClass | Java class the rule is associated with | For XPath rules, `"net.sourceforge.pmd.lang.rule.XPathRule"`; for Java rules, name of the Java class containing rule code. |
| description | Longer description of the issue this rule identifies | `"This is a bad practice because...."` |
| properties | Any PMD properties for the rule | `name="xpath"` and `value="//PrimaryPrefix[Name[starts-with(@Image,"System.out")]]"` (More info [here](https://pmd.github.io/pmd-6.32.0/pmd_userdocs_configuring_rules.html#rule-properties).) |

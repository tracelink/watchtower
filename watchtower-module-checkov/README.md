# Watchtower Module: ESLint

This module integrates with the [Checkov](https://www.checkov.io/)
scanner to scan infrastructure-as-code files (such as Terraform or Kubernetes) for common issues.
There are many [checks](https://github.com/bridgecrewio/checkov/tree/master/checkov) built-in to
Checkov that can be easily configured as core rules within Watchtower. Custom Checkov rules are not
currently supported by Watchtower.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [Module Name](#module-name)
- [Database Schema History Table](#database-schema-history-table)
- [Database Migrations Location](#database-migrations-location)
- [Additional Rule Fields](#additional-rule-fields)

## Module Name

Checkov

## Database Schema History Table

`checkov_schema_history`

## Database Migrations Location

`db/checkov`

## Additional Rule Fields

| Field | Description | Example | 
|--------|------------|---------|
| core | Boolean indicating whether this is a core Checkov check | `true` if this is a core rule; `false` otherwise |
| type | The category the check belongs to | See [Policies](https://www.checkov.io/1.Introduction/Policies.html) for more info. |
| entity | The supported resource entities for the check | See [Policies](https://www.checkov.io/1.Introduction/Policies.html) for more info. |
| iac | The IaC type that would be tested under the check | `"terraform"` or `"cloudformation"` |
| code | The Python code defining a custom Checkov rule | See [Policies](https://www.checkov.io/1.Introduction/Policies.html) for more info. |

Note that the name of a core Checkov rule in Watchtower must match the ID of the built-in Checkov
check. This ID follows the pattern `CKV_providerType_serialNumber` (e.g. `"CKV_AWS_9"`
, `"CKV_GCP_12"`).

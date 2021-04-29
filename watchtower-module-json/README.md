# Watchtower Module: JSON

This module matches code against JSONPath expressions and reports on any findings. JSON rules can be
designed and imported into Watchtower to scan any file type.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [Module Name](#module-name)
- [Database Schema History Table](#database-schema-history-table)
- [Database Migrations Location](#database-migrations-location)
- [Additional Rule Fields](#additional-rule-fields)

## Module Name

JSON

## Database Schema History Table

`json_schema_history`

## Database Migrations Location

`db/json`

## Additional Rule Fields

| Field | Description | Example | 
|--------|------------|---------|
| fileExtension | Comma-separated list of file extensions for any file type that this rule should be applied to | `""` to apply rule to all file types, or "txt" to apply only to files with a `.txt` extension |
| query | The JSONPath expression to match against | `"$.people.*.[?(@.age>45)]"` |

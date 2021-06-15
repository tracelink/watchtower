# Watchtower CLI

Watchtower provides a CLI to easily integrate Watchtower upload scans into the development phase for
code projects.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Parameters

- `watchtowerUrl`: The URL for your Watchtower server. This is required
- `apiKeyId`: Your Watchtower API key ID. This is required
- `apiSecret`: Your Watchtower API secret. This is required
- `target`: The target directory or file to zip and upload to Watchtower. This is required
- `output`: The output directory or file to store any violations or errors from Watchtower as a CSV
  file. If not specified, the results will be logged to the console
- `fileName`: The name to be used for the file uploaded to Watchtower. If not specified, defaults to
  the name of the base directory of the Maven project
- `ruleset`: The ruleset to apply for the Watchtower scan. If not specified, the default ruleset
  configured in Watchtower will be applied

## Executing the CLI

Below is an example of how to execute the CLI with parameters:

```
java -jar watchtower-cli.jar -u watchtowerUrl -k apiKeyId -s apiSecret -t target [-o output] [-n fileName] [-r ruleset]
```

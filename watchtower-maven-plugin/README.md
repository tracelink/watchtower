# Watchtower Maven Plugin

Watchtower provides a Maven plugin to easily integrate Watchtower upload scans into the development
phase for Maven projects.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Parameters

- `watchtowerUrl`: The URL for your Watchtower server. This is required and must be configured in
  the project `pom.xml`
- `watchtowerApiKeyId`: Your Watchtower API key ID. This is required and should be configured in the
  Maven `settings.xml` file
- `watchtowerApiSecret`: Your Watchtower API secret. This is required and should be configured in
  the Maven `settings.xml` file
- `target`: The target directory or file to zip and upload to Watchtower. If not specified, defaults
  to the base directory of the Maven project
- `output`: The output directory or file to store any violations or errors from Watchtower as a CSV
  file. If not specified, the results will be logged to the console
- `fileName`: The name to be used for the file uploaded to Watchtower. If not specified, defaults to
  the name of the base directory of the Maven project
- `ruleset`: The ruleset to apply for the Watchtower scan. If not specified, the default ruleset
  configured in Watchtower will be applied

## Configuration

Below is sample configuration of the plugin in a Maven `pom.xml` file.

```xml

<plugins>
	...
	<plugin>
		<groupId>com.tracelink.appsec</groupId>
		<artifactId>watchtower-maven-plugin</artifactId>
		<version>2.3.0-SNAPSHOT</version>
		<!-- Prevents the scan from being run multiple times for multi-module Maven projects -->
		<inherited>false</inherited>
		<configuration>
			<watchtowerUrl>https://my-watchtower-server.org</watchtowerUrl>
			<target>path/to/target</target>
			<output>path/to/output</output>
			<fileName>myScan.zip</fileName>
			<ruleset>Ruleset Name</ruleset>
		</configuration>
		<executions>
			<execution>
				<goals>
					<goal>watchtower-upload-scan</goal>
				</goals>
			</execution>
		</executions>
	</plugin>
	...
</plugins>

```

## Executing the Plugin

To execute the plugin, configure your plugin in the `pom.xml` and `settings.xml` files and then
simply run `mvn clean compile` from the base directory of the Maven project.

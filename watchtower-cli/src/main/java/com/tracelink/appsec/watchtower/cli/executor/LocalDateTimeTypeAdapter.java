package com.tracelink.appsec.watchtower.cli.executor;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Type adapter to translate {@link LocalDateTime} objects to and from strings for use in JSON
 * format.
 *
 * @author mcool
 */
public class LocalDateTimeTypeAdapter extends TypeAdapter<LocalDateTime> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(JsonWriter out, LocalDateTime value) throws IOException {
		if (value == null) {
			out.nullValue();
		} else {
			out.value(value.toString());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public LocalDateTime read(JsonReader in) throws IOException {
		if (in.peek().equals(JsonToken.NULL)) {
			in.nextNull();
			return null;
		} else {
			return LocalDateTime.parse(in.nextString());
		}
	}
}

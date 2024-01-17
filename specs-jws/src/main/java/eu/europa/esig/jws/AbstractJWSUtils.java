/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.jws;

import com.github.erosb.jsonsKema.IJsonValue;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonParser;
import com.github.erosb.jsonsKema.JsonValue;
import com.github.erosb.jsonsKema.Schema;
import com.github.erosb.jsonsKema.SchemaClient;
import com.github.erosb.jsonsKema.SchemaLoader;
import com.github.erosb.jsonsKema.SchemaLoaderConfig;
import com.github.erosb.jsonsKema.ValidationFailure;
import com.github.erosb.jsonsKema.Validator;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Abstract class for JWS signature validation against JSON schemas
 */
public abstract class AbstractJWSUtils {
	
	/**
	 * JSON Schema for a root JWS element validation
	 */
	private Schema jwsSchema;
	
	/**
	 * JSON Schema for a JWS Protected Header validation
	 */
	private Schema jwsProtectedHeaderSchema;
	
	/**
	 * JSON Schema for a JWS Unprotected Header validation
	 */
	private Schema jwsUnprotectedHeaderSchema;

	/**
	 * Default constructor instantiating the object with null values
	 */
	protected AbstractJWSUtils() {
		// empty
	}
	
	/**
	 * Returns a JWS Schema for a root signature element validation
	 * 
	 * @return {@link Schema} for JWS root validation
	 */
	public Schema getJWSSchema() {
		if (jwsSchema == null) {
			jwsSchema = loadSchema(getJWSSchemaJSON(), getJWSSchemaDefinitions());
		}
		return jwsSchema;
	}
	
	/**
	 * Returns a JWS Protected Header Schema
	 * 
	 * @return {@link Schema} for JWS Protected Header validation
	 */
	public Schema getJWSProtectedHeaderSchema() {
		if (jwsProtectedHeaderSchema == null) {
			jwsProtectedHeaderSchema = loadSchema(getJWSProtectedHeaderSchemaJSON(),
					getJWSProtectedHeaderSchemaDefinitions());
		}
		return jwsProtectedHeaderSchema;
	}

	/**
	 * Returns a JWS Protected Header Schema
	 * 
	 * @return {@link Schema} for JWS Protected Header validation
	 */
	public Schema getJWSUnprotectedHeaderSchema() {
		if (jwsUnprotectedHeaderSchema == null) {
			jwsUnprotectedHeaderSchema = loadSchema(getJWSUnprotectedHeaderSchemaJSON(),
					getJWSUnprotectedHeaderSchemaDefinitions());
		}
		return jwsUnprotectedHeaderSchema;
	}

	/**
	 * Returns a JSON schema for a root JWS element validation
	 * 
	 * @return {@link String}
	 */
	public abstract String getJWSSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS validation
	 * 
	 * @return JWS schema definitions map
	 */
	public abstract Map<URI, String> getJWSSchemaDefinitions();

	/**
	 * Loads JSON schema for a JSON Protected Header validation
	 * 
	 * @return {@link String}
	 */
	public abstract String getJWSProtectedHeaderSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS Protected Header validation
	 * 
	 * @return JWS Protected Header schema definitions map
	 */
	public abstract Map<URI, String> getJWSProtectedHeaderSchemaDefinitions();

	/**
	 * Loads JSON schema for a JSON Unprotected Header validation
	 * 
	 * @return {@link String}
	 */
	public abstract String getJWSUnprotectedHeaderSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS Unprotected Header validation
	 * 
	 * @return JWS Unprotected Header schema definitions map
	 */
	public abstract Map<URI, String> getJWSUnprotectedHeaderSchemaDefinitions();

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param is {@link InputStream} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(InputStream is) {
		return validateAgainstJWSSchema(parseJson(is));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param jsonString {@link String} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(String jsonString) {
		return validateAgainstJWSSchema(parseJson(jsonString));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param json {@link JsonObject} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(JsonObject json) {
		return validateAgainstSchema(json, getJWSSchema());
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param is {@link InputStream} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(InputStream is) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param jsonString {@link String} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(String jsonString) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(jsonString));
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param json {@link JsonObject} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(JsonObject json) {
		return validateAgainstSchema(json, getJWSProtectedHeaderSchema());
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param is {@link InputStream} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(InputStream is) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param jsonString {@link String} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(String jsonString) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(jsonString));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param json {@link JsonValue} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(JsonValue json) {
		return validateAgainstSchema(json, getJWSUnprotectedHeaderSchema());
	}
	
	/**
	 * Validates a {@code json} against the provided JSON {@code schema}
	 * 
	 * @param json   {@link JsonValue} to be validated against a schema
	 * @param schema {@link Schema} schema to validate against
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstSchema(JsonValue json, Schema schema) {
		Validator validator = Validator.forSchema(schema);
		ValidationFailure validationFailure = validator.validate(json);
		if (validationFailure != null) {
			Set<ValidationFailure> causes = validationFailure.getCauses();
			return causes.stream().map(v -> new ValidationMessage(v).getMessage()).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * Parses the JSON string and returns a {@code JsonObject}
	 * 
	 * @param json {@link String} to parse
	 * @return {@link JsonObject}
	 */
	public JsonObject parseJson(String json) {
		return parseJson(json, null);
	}

	/**
	 * Parses the JSON string with the provided schema {@code uri} identifier, and returns a {@code JsonObject}.
	 * This method is used for a schema parsing.
	 *
	 * @param json {@link String} to parse
	 * @param uri {@link URI} of the schema
	 * @return {@link JsonObject}
	 */
	public JsonObject parseJson(String json, URI uri) {
		return (JsonObject) new JsonParser(json, uri).parse();
	}

	/**
	 * Parses the JSON InputStream and returns a {@code JsonObject}
	 * 
	 * @param inputStream {@link InputStream} to parse
	 * @return {@link JsonObject}
	 */
	public JsonObject parseJson(InputStream inputStream) {
		return parseJson(inputStream, null);
	}

	/**
	 * Parses the JSON InputStream with the provided schema {@code uri} identifier, and returns a {@code JsonObject}.
	 * This method is used for a schema parsing.
	 *
	 * @param inputStream {@link InputStream} to parse
	 * @param uri {@link URI} of the schema
	 * @return {@link JsonObject}
	 */
	public JsonObject parseJson(InputStream inputStream, URI uri) {
		try (InputStream is = inputStream) {
			return parseJson(toString(is), uri);
		} catch (IOException e) {
			throw new IllegalStateException("Unable to read a scheme InputStream!");
		}
	}

	private String toString(InputStream is) throws IOException {
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		for (int length; (length = is.read(buffer)) != -1; ) {
			result.write(buffer, 0, length);
		}
		return result.toString(StandardCharsets.UTF_8.name());
	}
	
	/**
	 * Loads schema with the given list of definitions (references)
	 * 
	 * @param schemaJSON {@link JsonObject} the schema object URI
	 * @param definitions a map containing definitions and their reference names
	 * @return {@link Schema}
	 */
	public Schema loadSchema(String schemaJSON, Map<URI, String> definitions) {
		ResourceSchemaClient schemaClient = new ResourceSchemaClient(definitions);
		SchemaLoaderConfig schemaLoaderConfig = new SchemaLoaderConfig(schemaClient, "");

		IJsonValue parsed = schemaClient.getParsed(URI.create(schemaJSON));
		return new SchemaLoader(parsed, schemaLoaderConfig).load();
	}

	/**
	 * This is a helper class to load a schema from resources by the given URI
	 */
	private class ResourceSchemaClient implements SchemaClient {

		/** Map of schema URI identifiers and resources filename */
		private final Map<URI, String> resources;

		/**
		 * Default constructor
		 *
		 * @param resources a map between schema URI and resources filename
		 */
		ResourceSchemaClient(Map<URI, String> resources) {
			this.resources = resources;
		}

		@NotNull
		@Override
		public InputStream get(@NotNull URI uri) {
			String schema = resources.get(uri);
			if (schema != null) {
				InputStream is = AbstractJWSUtils.class.getResourceAsStream(schema);
				if (is != null) {
					return is;
				}
			}
			throw new IllegalStateException(String.format("Unable to load a schema for URI : %s", uri));
		}

		@NotNull
		@Override
		public IJsonValue getParsed(@NotNull URI uri) {
			return parseJson(get(uri), uri);
		}

	}
	
}

/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.jws;

import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonValue;
import com.github.erosb.jsonsKema.Schema;
import eu.europa.esig.json.JSONSchemaUtils;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;

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
			jwsSchema = JSONSchemaUtils.getInstance().loadSchema(getJWSSchemaJSON(), getJWSSchemaDefinitions());
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
			jwsProtectedHeaderSchema = JSONSchemaUtils.getInstance().loadSchema(getJWSProtectedHeaderSchemaJSON(),
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
			jwsUnprotectedHeaderSchema = JSONSchemaUtils.getInstance().loadSchema(getJWSUnprotectedHeaderSchemaJSON(),
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
		return validateAgainstJWSSchema(JSONSchemaUtils.getInstance().parseJson(is));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param jsonString {@link String} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(String jsonString) {
		return validateAgainstJWSSchema(JSONSchemaUtils.getInstance().parseJson(jsonString));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param json {@link JsonObject} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(JsonObject json) {
		return JSONSchemaUtils.getInstance().validateAgainstSchema(json, getJWSSchema());
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param is {@link InputStream} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(InputStream is) {
		return validateAgainstJWSProtectedHeaderSchema(JSONSchemaUtils.getInstance().parseJson(is));
	}

	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param jsonString {@link String} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(String jsonString) {
		return validateAgainstJWSProtectedHeaderSchema(JSONSchemaUtils.getInstance().parseJson(jsonString));
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param json {@link JsonObject} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(JsonObject json) {
		return JSONSchemaUtils.getInstance().validateAgainstSchema(json, getJWSProtectedHeaderSchema());
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param is {@link InputStream} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(InputStream is) {
		return validateAgainstJWSUnprotectedHeaderSchema(JSONSchemaUtils.getInstance().parseJson(is));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param jsonString {@link String} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(String jsonString) {
		return validateAgainstJWSUnprotectedHeaderSchema(JSONSchemaUtils.getInstance().parseJson(jsonString));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param json {@link JsonValue} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(JsonValue json) {
		return JSONSchemaUtils.getInstance().validateAgainstSchema(json, getJWSUnprotectedHeaderSchema());
	}
	
	/**
	 * Validates a {@code json} against the provided JSON {@code schema}
	 * 
	 * @param json   {@link JsonValue} to be validated against a schema
	 * @param schema {@link Schema} schema to validate against
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().validateAgainstSchema(json, schema)}
	 */
	@Deprecated
	public List<String> validateAgainstSchema(JsonValue json, Schema schema) {
		return JSONSchemaUtils.getInstance().validateAgainstSchema(json, schema);
	}

	/**
	 * Returns a list of RFC 7515 and RFC 7517 definitions
	 *
	 * @return a map of definitions
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getJSONSchemaDefinitions()}
	 */
	@Deprecated
	public Map<URI, String> getJSONSchemaDefinitions() {
		return JSONSchemaUtils.getInstance().getJSONSchemaDefinitions();
	}

	/**
	 * Parses the JSON string and returns a {@code JsonObject}
	 * 
	 * @param json {@link String} to parse
	 * @return {@link JsonObject}
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().parseJson(json)}
	 */
	@Deprecated
	public JsonObject parseJson(String json) {
		return JSONSchemaUtils.getInstance().parseJson(json);
	}

	/**
	 * Parses the JSON string with the provided schema {@code uri} identifier, and returns a {@code JsonObject}.
	 * This method is used for a schema parsing.
	 *
	 * @param json {@link String} to parse
	 * @param uri {@link URI} of the schema
	 * @return {@link JsonObject}
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().parseJson(json, uri)}
	 */
	@Deprecated
	public JsonObject parseJson(String json, URI uri) {
		return JSONSchemaUtils.getInstance().parseJson(json, uri);
	}

	/**
	 * Parses the JSON InputStream and returns a {@code JsonObject}
	 * 
	 * @param inputStream {@link InputStream} to parse
	 * @return {@link JsonObject}
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().parseJson(inputStream)}
	 */
	@Deprecated
	public JsonObject parseJson(InputStream inputStream) {
		return JSONSchemaUtils.getInstance().parseJson(inputStream);
	}

	/**
	 * Parses the JSON InputStream with the provided schema {@code uri} identifier, and returns a {@code JsonObject}.
	 * This method is used for a schema parsing.
	 *
	 * @param inputStream {@link InputStream} to parse
	 * @param uri {@link URI} of the schema
	 * @return {@link JsonObject}
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().parseJson(inputStream, uri)}
	 */
	@Deprecated
	public JsonObject parseJson(InputStream inputStream, URI uri) {
		return JSONSchemaUtils.getInstance().parseJson(inputStream, uri);
	}
	
	/**
	 * Loads schema with the given list of definitions (references)
	 * 
	 * @param schemaJSON {@link JsonObject} the schema object URI
	 * @param definitions a map containing definitions and their reference names
	 * @return {@link Schema}
	 * @deprecated since DSS 6.3. Please use {@code JSONUtils.getInstance().loadSchema(schemaJSON, definitions)}
	 */
	@Deprecated
	public Schema loadSchema(String schemaJSON, Map<URI, String> definitions) {
		return JSONSchemaUtils.getInstance().loadSchema(schemaJSON, definitions);
	}

}

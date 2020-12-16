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

import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.everit.json.schema.loader.SchemaLoader.SchemaLoaderBuilder;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
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
	 * @return {@link JSONObject}
	 */
	public abstract JSONObject getJWSSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS validation
	 * 
	 * @return JWS schema definitions map
	 */
	public abstract Map<URI, JSONObject> getJWSSchemaDefinitions();

	/**
	 * Loads JSON schema for a JSON Protected Header validation
	 * 
	 * @return {@link JSONObject}
	 */
	public abstract JSONObject getJWSProtectedHeaderSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS Protected Header validation
	 * 
	 * @return JWS Protected Header schema definitions map
	 */
	public abstract Map<URI, JSONObject> getJWSProtectedHeaderSchemaDefinitions();

	/**
	 * Loads JSON schema for a JSON Unprotected Header validation
	 * 
	 * @return {@link JSONObject}
	 */
	public abstract JSONObject getJWSUnprotectedHeaderSchemaJSON();
	
	/**
	 * Returns a map of definition objects used for JWS Unprotected Header validation
	 * 
	 * @return JWS Unprotected Header schema definitions map
	 */
	public abstract Map<URI, JSONObject> getJWSUnprotectedHeaderSchemaDefinitions();

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
	 * @param json {@link JSONObject} representing a JSON to validate
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(JSONObject json) {
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
	 * @param json {@link JSONObject} representing a protected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(JSONObject json) {
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
	 * @param json {@link JSONObject} representing an unprotected header of a JWS
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(JSONObject json) {
		return validateAgainstSchema(json, getJWSUnprotectedHeaderSchema());
	}
	
	/**
	 * Validates a {@code json} against the provided JSON {@code schema}
	 * 
	 * @param json   {@link JSONObject} to be validated against a schema
	 * @param schema {@link Schema} schema to validate against
	 * @return a list of {@link String} messages containing errors occurred during
	 *         the validation process, empty list when validation succeeds
	 */
	public List<String> validateAgainstSchema(JSONObject json, Schema schema) {
		try {
			schema.validate(json);
			
		} catch (ValidationException e) {
			return e.getAllMessages();
			
		} catch (Exception e) {
			return Collections.singletonList(e.getMessage());
		}
		
		return Collections.emptyList();
	}

	/**
	 * Parses the JSON string and returns a {@code JSONObject}
	 * 
	 * @param json {@link String} to parse
	 * @return {@link JSONObject}
	 */
	public JSONObject parseJson(String json) {
		return new JSONObject(new JSONTokener(json));
	}

	/**
	 * Parses the JSON InputStream and returns a {@code JSONObject}
	 * 
	 * @param inputStream {@link InputStream} to parse
	 * @return {@link JSONObject}
	 */
	public JSONObject parseJson(InputStream inputStream) {
		return new JSONObject(new JSONTokener(inputStream));
	}
	
	/**
	 * Loads schema with the given list of definitions (references)
	 * 
	 * @param schemaJSON  {@link JSONObject} the schema object
	 * @param definitions a map containing definitions and their reference names
	 * @return {@link Schema}
	 */
	public Schema loadSchema(JSONObject schemaJSON, Map<URI, JSONObject> definitions) {
		SchemaLoaderBuilder builder = SchemaLoader.builder()
				.schemaJson(schemaJSON)
				.draftV7Support();
		
		for (Map.Entry<URI, JSONObject> definition : definitions.entrySet()) {
			builder.registerSchemaByURI(definition.getKey(), definition.getValue());
		}
		
		SchemaLoader loader = builder.build();
		return loader.load().build();
	}
	
}

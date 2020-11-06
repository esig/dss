package eu.europa.esig.jws;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;

import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.everit.json.schema.loader.SchemaLoader.SchemaLoaderBuilder;
import org.json.JSONObject;
import org.json.JSONTokener;

public abstract class AbstractJWSUtils {

	private static final String EMPTY_STRING = "";
	
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
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSSchema(InputStream is) {
		return validateAgainstJWSSchema(parseJson(is));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param jsonString {@link String} representing a JSON to validate
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSSchema(String jsonString) {
		return validateAgainstJWSSchema(parseJson(jsonString));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param json {@link JSONObject} representing a JSON to validate
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSSchema(JSONObject json) {
		return validateAgainstSchema(json, getJWSSchema());
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param is {@link InputStream} representing a protected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSProtectedHeaderSchema(InputStream is) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param jsonString {@link String} representing a protected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSProtectedHeaderSchema(String jsonString) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(jsonString));
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param json {@link JSONObject} representing a protected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSProtectedHeaderSchema(JSONObject json) {
		return validateAgainstSchema(json, getJWSProtectedHeaderSchema());
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param is {@link InputStream} representing an unprotected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSUnprotectedHeaderSchema(InputStream is) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param jsonString {@link String} representing an unprotected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSUnprotectedHeaderSchema(String jsonString) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(jsonString));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param json {@link JSONObject} representing an unprotected header of a JWS
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	public String validateAgainstJWSUnprotectedHeaderSchema(JSONObject json) {
		return validateAgainstSchema(json, getJWSUnprotectedHeaderSchema());
	}
	
	/**
	 * Validates a {@code json} against the provided JSON {@code schema}
	 * 
	 * @param json   {@link JSONObject} to be validated against a schema
	 * @param schema {@link Schema} schema to validate against
	 * @return {@link String} a message containing errors occurred during the
	 *         validation process, empty string ("") when validation succeeds
	 */
	public String validateAgainstSchema(JSONObject json, Schema schema) {
		try {
			schema.validate(json);
			
		} catch (ValidationException e) {
			List<String> allMessages = e.getAllMessages();
			if (allMessages != null && allMessages.size() != 0) {
				return allMessages.toString();
			}
			
		} catch (Exception e) {
			return e.getMessage();
		}
		
		return EMPTY_STRING;
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

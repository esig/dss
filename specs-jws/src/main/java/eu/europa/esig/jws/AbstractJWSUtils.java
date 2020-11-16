package eu.europa.esig.jws;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.everit.json.schema.loader.SchemaLoader.SchemaLoaderBuilder;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractJWSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractJWSUtils.class);
	
	private static final String JWS_SCHEMA_LOCATION = "/schema/rfc7515-jws.json";

	private static final String ERROR_MESSAGE = "Error during the XML schema validation! Reason : {}";
	
	protected abstract JSONObject getJWSProtectedHeaderSchema();
	
	protected abstract Map<URI, JSONObject> getJWSProtectedHeaderDefinitions();
	
	protected abstract JSONObject getJWSUnprotectedHeaderSchema();
	
	protected abstract Map<URI, JSONObject> getJWSUnprotectedHeaderDefinitions();

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param is {@link InputStream} representing a JSON to validate
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(InputStream is) {
		return validateAgainstJWSSchema(parseJson(is));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param jsonString {@link String} representing a JSON to validate
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSSchema(String jsonString) {
		return validateAgainstJWSSchema(parseJson(jsonString));
	}

	/**
	 * Validates a JSON against JWS Schema according to RFC 7515
	 * 
	 * @param json {@link JSONObject} representing a JSON to validate
	 * @return {@link String} a message containing errors occurred during the validation process, 
	 * 			empty string ("") when validation succeeds
	 */
	protected List<String> validateAgainstJWSSchema(JSONObject json) {
		JSONObject jwsSchema = getJWSSchema();
		return validateAgainstSchema(json, jwsSchema, Collections.emptyMap());
	}
	
	/**
	 * Returns JWS schema
	 * 
	 * @return {@link JSONObject}
	 */
	protected JSONObject getJWSSchema() {
		return parseJson(AbstractJWSUtils.class.getResourceAsStream(JWS_SCHEMA_LOCATION));
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param is {@link InputStream} representing a protected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(InputStream is) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param jsonString {@link String} representing a protected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSProtectedHeaderSchema(String jsonString) {
		return validateAgainstJWSProtectedHeaderSchema(parseJson(jsonString));
	}
	
	/**
	 * Validates a "protected" header of a JWS
	 * 
	 * @param json {@link JSONObject} representing a protected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	protected List<String> validateAgainstJWSProtectedHeaderSchema(JSONObject json) {
		JSONObject jwsProtectedSchema = getJWSProtectedHeaderSchema();
		Map<URI, JSONObject> jwsProtectedDefinitions = getJWSProtectedHeaderDefinitions();
		return validateAgainstSchema(json, jwsProtectedSchema, jwsProtectedDefinitions);
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param is {@link InputStream} representing an unprotected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(InputStream is) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(is));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param jsonString {@link String} representing an unprotected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstJWSUnprotectedHeaderSchema(String jsonString) {
		return validateAgainstJWSUnprotectedHeaderSchema(parseJson(jsonString));
	}

	/**
	 * Validates an unprotected "header" of a JWS
	 * 
	 * @param json {@link JSONObject} representing an unprotected header of a JWS
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	protected List<String> validateAgainstJWSUnprotectedHeaderSchema(JSONObject json) {
		JSONObject jwsUnprotectedSchema = getJWSUnprotectedHeaderSchema();
		Map<URI, JSONObject> jwsUnprotectedDefinitions = getJWSUnprotectedHeaderDefinitions();
		return validateAgainstSchema(json, jwsUnprotectedSchema, jwsUnprotectedDefinitions);
	}
	
	/**
	 * Validates a {@code json} against the provided JSON {@code schema}
	 * 
	 * @param json        {@link JSONObject} to be validated against a schema
	 * @param schema      {@link JSONObject} schema to validate against
	 * @param definitions a map of definitions required for the {@code schema}
	 * @return a list of {@link String} message errors occurred during the
	 *         validation process, an empty list when validation succeeds
	 */
	public List<String> validateAgainstSchema(JSONObject json, JSONObject schema, Map<URI, JSONObject> definitions) {
		try {
			Schema jwsProtectedSchema = loadSchema(schema, definitions);
			jwsProtectedSchema.validate(json);
			return Collections.emptyList();
			
		} catch (ValidationException e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn(ERROR_MESSAGE, e.getMessage(), e);
			} else {
				LOG.warn(ERROR_MESSAGE, e.getMessage());
			}
			return e.getAllMessages();
			
		} catch (Exception e) {
			LOG.warn(ERROR_MESSAGE, e.getMessage(), e);
			return Arrays.asList(e.getMessage());
		}
	}

	protected JSONObject parseJson(String json) {
		return new JSONObject(new JSONTokener(json));
	}
	
	protected JSONObject parseJson(InputStream inputStream) {
		return new JSONObject(new JSONTokener(inputStream));
	}
	
	protected Schema loadSchema(JSONObject schemaJSON, Map<URI, JSONObject> definitions) throws URISyntaxException {
		SchemaLoaderBuilder builder = SchemaLoader.builder()
				.schemaJson(schemaJSON)
				.draftV7Support();
		
		if (definitions != null) {
			for (Map.Entry<URI, JSONObject> definition : definitions.entrySet()) {
				builder.registerSchemaByURI(definition.getKey(), definition.getValue());
			}
		}
		
		SchemaLoader loader = builder.build();
		return loader.load().build();
	}
	
}

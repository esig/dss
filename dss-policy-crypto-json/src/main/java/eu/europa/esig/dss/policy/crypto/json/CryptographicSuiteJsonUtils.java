package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.Schema;
import eu.europa.esig.json.JSONSchemaUtils;

import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class contains utils for parsing and validation of the cryptographic suites according to
 * the ETSI TS 119 322 JSON schema
 *
 */
public final class CryptographicSuiteJsonUtils {

    /** Cryptographic suite schema URI */
    private static final String SCHEMA_URI = "http://uri.etsi.org/19322/algoCatSchema";

    /** Cryptographic suite schema's location */
    private static final String SCHEMA_LOCATION = "/schema/19322algocatjsonschema.json";

    /**
     * JSON Schema for a root JSON Cryptographic suite element validation
     */
    private Schema schema;

    /** Map of used definition schemas */
    private Map<URI, String> definitions;

    /** Singleton instance */
    private static CryptographicSuiteJsonUtils singleton;

    /**
     * Empty constructor
     */
    private CryptographicSuiteJsonUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CryptographicSuiteJsonUtils}
     *
     * @return {@link CryptographicSuiteJsonUtils}
     */
    public static CryptographicSuiteJsonUtils getInstance() {
        if (singleton == null) {
            singleton = new CryptographicSuiteJsonUtils();
        }
        return singleton;
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param is {@link InputStream} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(InputStream is) {
        return validateAgainstSchema(JSONSchemaUtils.getInstance().parseJson(is));
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param jsonString {@link String} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(String jsonString) {
        return validateAgainstSchema(JSONSchemaUtils.getInstance().parseJson(jsonString));
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param json {@link JsonObject} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(JsonObject json) {
        return JSONSchemaUtils.getInstance().validateAgainstSchema(json, getSchema());
    }

    /**
     * Returns a JWS Schema for a root signature element validation
     *
     * @return {@link Schema} for JWS root validation
     */
    public Schema getSchema() {
        if (schema == null) {
            schema = JSONSchemaUtils.getInstance().loadSchema(SCHEMA_URI, getRFCDefinitions());
        }
        return schema;
    }

    /**
     * Returns a list of JSON schema definitions
     *
     * @return a map of definitions
     */
    private Map<URI, String> getRFCDefinitions() {
        if (definitions == null) {
            definitions = new HashMap<>();
            definitions.putAll(JSONSchemaUtils.getInstance().getJSONSchemaDefinitions());
            definitions.put(URI.create(SCHEMA_URI), SCHEMA_LOCATION);
        }
        return definitions;
    }

}

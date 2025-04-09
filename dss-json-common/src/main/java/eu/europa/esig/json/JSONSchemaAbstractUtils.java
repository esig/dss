package eu.europa.esig.json;

import com.github.erosb.jsonsKema.IJsonValue;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonValue;
import com.github.erosb.jsonsKema.Schema;
import com.github.erosb.jsonsKema.SchemaClient;
import com.github.erosb.jsonsKema.SchemaLoader;
import com.github.erosb.jsonsKema.SchemaLoaderConfig;
import com.github.erosb.jsonsKema.ValidationFailure;
import com.github.erosb.jsonsKema.Validator;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class contains util methods for parsing and validation of JSON documents
 *
 */
public abstract class JSONSchemaAbstractUtils {

    /** The JSON Draft 07 schema of definitions */
    private static final String JSON_DRAFT_07_SCHEMA_LOCATION = "/schema/json-schema-draft-07.json";

    /** The JSON Draft 07 schema name URI */
    private static final String JSON_DRAFT_07_SCHEMA_URI = "http://json-schema.org/draft-07/schema#";

    /** JSON Schema validator */
    private Validator validator;

    /** Map of used definition schemas */
    private Map<URI, String> definitions;

    /**
     * Empty constructor
     */
    protected JSONSchemaAbstractUtils() {
        // empty
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param is {@link InputStream} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(InputStream is) {
        return validateAgainstSchema(new JSONParser().parse(is));
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param jsonString {@link String} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(String jsonString) {
        return validateAgainstSchema(new JSONParser().parse(jsonString));
    }

    /**
     * Validates a JSON against JWS Schema according to ETSI TS 119 322 JSON schema
     *
     * @param json {@link JsonObject} representing a JSON to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(JsonObject json) {
        return validateAgainstSchema(json, getSchema());
    }

    /**
     * Gets the schema according to the current JSON specification
     *
     * @return {@link Schema}
     */
    protected Schema getSchema() {
        return loadSchema(getSchemaURI(), getSchemaDefinitions());
    }

    /**
     * Gets URI for the current schema
     *
     * @return {@link String}
     */
    public abstract String getSchemaURI();

    /**
     * Gets a list of schema definitions
     *
     * @return a map between schema URI's and their filesystem locations
     */
    public abstract Map<URI, String> getSchemaDefinitions();

    /**
     * Gets a validator for the given JSON schema
     *
     * @return {@link Validator}
     */
    protected Validator getValidator() {
        if (validator == null) {
            validator = Validator.forSchema(getSchema());
        }
        return validator;
    }

    /**
     * Validates a {@code json} against the provided JSON {@code schema}
     *
     * @param json   {@link JsonValue} to be validated against a schema
     * @param schema {@link Schema} schema to validate against
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    protected List<String> validateAgainstSchema(JsonValue json, Schema schema) {
        Validator validator = getValidator();
        ValidationFailure validationFailure = validator.validate(json);
        if (validationFailure != null) {
            Set<ValidationFailure> causes = validationFailure.getCauses();
            return causes.stream().map(v -> new ValidationMessage(v).getMessage()).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Returns a JSON Draft 7 Schema definition
     *
     * @return a map of definitions
     */
    public Map<URI, String> getJSONSchemaDefinitions() {
        if (definitions == null) {
            definitions = new HashMap<>();
            definitions.put(URI.create(JSON_DRAFT_07_SCHEMA_URI), JSON_DRAFT_07_SCHEMA_LOCATION);
        }
        return definitions;
    }

    /**
     * Loads schema with the given list of definitions (references)
     *
     * @param schemaJSON {@link JsonObject} the schema object URI
     * @param definitions a map containing definitions and their reference names
     * @return {@link Schema}
     */
    protected Schema loadSchema(String schemaJSON, Map<URI, String> definitions) {
        ResourceSchemaClient schemaClient = new ResourceSchemaClient(definitions);
        SchemaLoaderConfig schemaLoaderConfig = new SchemaLoaderConfig(schemaClient, URI.create(""));

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
                InputStream is = JSONSchemaAbstractUtils.class.getResourceAsStream(schema);
                if (is != null) {
                    return is;
                }
            }
            throw new IllegalStateException(String.format("Unable to load a schema for URI : %s", uri));
        }

        @NotNull
        @Override
        public IJsonValue getParsed(@NotNull URI uri) {
            return new JSONParser().parse(get(uri), uri);
        }

    }

}

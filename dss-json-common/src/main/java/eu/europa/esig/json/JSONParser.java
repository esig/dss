package eu.europa.esig.json;

import com.github.erosb.jsonsKema.JsonObject;

import java.io.InputStream;

/**
 * Parses a JSON document and returns a Java object representing the parsed result
 * This class does not perform validation against a JSON schema.
 *
 */
public class JSONParser {

    /**
     * Empty constructor
     */
    public JSONParser() {
        // empty
    }

    /**
     * Parses {@code InputStream} and returns a {@code JsonObjectWrapper} if applicable
     *
     * @param inputStream {@link InputStream} to parse
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper parse(InputStream inputStream) {
        JsonObject json = JSONSchemaUtils.getInstance().parseJson(inputStream);
        if (json != null) {
            return new JsonObjectWrapper(json);
        }
        throw new IllegalArgumentException("Unable to parse InputStream as JSON!");
    }

}

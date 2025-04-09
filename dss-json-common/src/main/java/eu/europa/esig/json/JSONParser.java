package eu.europa.esig.json;

import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Parses a JSON document and returns a Java object representing the parsed result
 * This class does not perform validation against a JSON schema.
 *
 */
public class JSONParser {

    /** Empty URI reference */
    private static final URI EMPTY_URI;

    static {
        EMPTY_URI = URI.create("");
    }

    /**
     * Empty constructor
     */
    public JSONParser() {
        // empty
    }

    /**
     * Parses the JSON string and returns a {@code JsonObject}
     *
     * @param json {@link String} to parse
     * @return {@link JsonObject}
     */
    protected JsonObject parse(String json) {
        return parse(json, EMPTY_URI);
    }

    /**
     * Parses the JSON string with the provided schema {@code uri} identifier, and returns a {@code JsonObject}.
     * This method is used for a schema parsing.
     *
     * @param json {@link String} to parse
     * @param uri {@link URI} of the schema
     * @return {@link JsonObject}
     */
    protected JsonObject parse(String json, URI uri) {
        return (JsonObject) new JsonParser(json, uri).parse();
    }

    /**
     * Parses {@code InputStream} and returns a {@code JsonObject} if applicable
     *
     * @param inputStream {@link InputStream} to parse
     * @return {@link JsonObject}
     */
    public JsonObject parse(InputStream inputStream) {
        return parse(inputStream, EMPTY_URI);
    }

    /**
     * Parses {@code InputStream} and returns a {@code JsonObject} if applicable
     *
     * @param inputStream {@link InputStream} to parse
     * @return {@link JsonObject}
     */
    public JsonObject parse(InputStream inputStream, URI uri) {
        try (InputStream is = inputStream) {
            return (JsonObject) new JsonParser(is, uri).parse();
        } catch (IOException e) {
            throw new IllegalArgumentException(String.format("Unable to read a scheme InputStream! Reason : %s", e.getMessage()), e);
        }
    }

}

package eu.europa.esig.json;

import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonParseException;
import com.github.erosb.jsonsKema.JsonParser;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.util.Objects;

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
     * Parses the JSON string and returns a {@code JsonObjectWrapper}
     *
     * @param json {@link String} to parse
     * @return {@link JsonObjectWrapper}
     */
    protected JsonObjectWrapper parse(String json) {
        return parse(json, EMPTY_URI);
    }

    /**
     * Parses the JSON string with the provided schema {@code uri} identifier, and returns a {@code JsonObjectWrapper}.
     * This method is used for a schema parsing.
     *
     * @param json {@link String} to parse
     * @param uri {@link URI} of the schema
     * @return {@link JsonObjectWrapper}
     */
    protected JsonObjectWrapper parse(String json, URI uri) {
        Objects.requireNonNull(json, "JSON String cannot be null!");
        Objects.requireNonNull(uri, "URI cannot be null!");
        try {
            return new JsonObjectWrapper((JsonObject) new JsonParser(json, uri).parse());
        } catch (JsonParseException e) {
            throw new IllegalArgumentException(String.format("Unable to parse JSON document! Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Parses {@code File} and returns a {@code JsonObjectWrapper} if applicable
     *
     * @param file {@link File} to parse
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper parse(File file) {
        return parse(file, EMPTY_URI);
    }

    /**
     * Parses {@code InputStream} against a schema with {@code URI} identifier and
     * returns a {@code JsonObjectWrapper} if applicable
     *
     * @param file {@link File} to parse
     * @param uri {@link URI} scheme URI to parse against
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper parse(File file, URI uri) {
        Objects.requireNonNull(file, "File cannot be null!");
        Objects.requireNonNull(uri, "URI cannot be null!");
        try (InputStream is = Files.newInputStream(file.toPath())) {
            return parse(is, uri);
        } catch (IOException e) {
            throw new IllegalArgumentException(String.format("Unable to parse a file with name '%s'", file.getName()));
        }
    }

    /**
     * Parses {@code InputStream} and returns a {@code JsonObjectWrapper} if applicable
     *
     * @param inputStream {@link InputStream} to parse
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper parse(InputStream inputStream) {
        return parse(inputStream, EMPTY_URI);
    }

    /**
     * Parses {@code InputStream} against a schema with {@code URI} and
     * returns a {@code JsonObjectWrapper} if applicable
     *
     * @param inputStream {@link InputStream} to parse
     * @param uri {@link URI} scheme URI to parse against
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper parse(InputStream inputStream, URI uri) {
        Objects.requireNonNull(inputStream, "InputStream cannot be null!");
        Objects.requireNonNull(uri, "URI cannot be null!");
        try (InputStream is = inputStream) {
            return new JsonObjectWrapper((JsonObject) new JsonParser(is, uri).parse());
        } catch (IOException e) {
            throw new IllegalArgumentException(String.format("Unable to read a scheme InputStream! Reason : %s", e.getMessage()), e);
        } catch (JsonParseException e) {
            throw new IllegalArgumentException(String.format("Unable to parse JSON document! Reason : %s", e.getMessage()), e);
        }
    }

}

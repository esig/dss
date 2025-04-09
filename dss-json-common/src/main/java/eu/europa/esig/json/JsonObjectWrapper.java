package eu.europa.esig.json;

import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonNumber;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Wraps a {@code com.github.erosb.jsonsKema.JsonObject} and provides utility methods for working with it
 *
 */
public class JsonObjectWrapper {

    private static final Logger LOG = LoggerFactory.getLogger(JsonObjectWrapper.class);

    /** Wrapped JSON object */
    private final JsonObject jsonObject;

    /**
     * Default constructor
     *
     * @param jsonObject {@link com.github.erosb.jsonsKema.JsonObject}
     */
    public JsonObjectWrapper(final JsonObject jsonObject) {
        Objects.requireNonNull(jsonObject, "JSON object cannot be null!");
        this.jsonObject = jsonObject;
    }

    /**
     * Gets a value of the header {@code name} as a Json Object.
     * If not present, or not able to convert, returns NULL.
     *
     * @param name {@link String} header name to get a value for
     * @return {@link JsonObjectWrapper}
     */
    public JsonObjectWrapper getAsObject(String name) {
        JsonValue jsonValue = jsonObject.get(name);
        return toObject(jsonValue);
    }

    private JsonObjectWrapper toObject(JsonValue jsonValue) {
        if (jsonValue == null) {
            // continue

        } else if (jsonValue instanceof JsonObject) {
            return new JsonObjectWrapper((JsonObject) jsonValue);

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to process an obtained item with value : '{}'. The JSON Object type is expected!", jsonValue);
            } else {
                LOG.warn("Unable to process an obtained item. The JSON Object type is expected!");
            }
        }
        return null;
    }

    /**
     * Gets a value of the header {@code name} as a String.
     * If not present, or not able to convert, returns NULL.
     *
     * @param name {@link String} header name to get a value for
     * @return {@link String}
     */
    public String getAsString(String name) {
        JsonValue jsonValue = jsonObject.get(name);
        if (jsonValue == null) {
            // continue

        } else if (jsonValue instanceof JsonString) {
            return ((JsonString) jsonValue).getValue();

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to process an obtained item with value : '{}'. The JSON String type is expected!", jsonValue);
            } else {
                LOG.warn("Unable to process an obtained item. The JSON String type is expected!");
            }
        }

        return null;
    }

    /**
     * Gets a value of the header {@code name} as a Number.
     * If not present, or not able to convert, returns NULL.
     *
     * @param name {@link String} header name to get a value for
     * @return {@link Number}
     */
    public Number getAsNumber(String name) {
        JsonValue jsonValue = jsonObject.get(name);
        if (jsonValue == null) {
            // continue

        } else if (jsonValue instanceof JsonNumber) {
            return ((JsonNumber) jsonValue).getValue();

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to process an obtained item with value : '{}'. The JSON Number type is expected!", jsonValue);
            } else {
                LOG.warn("Unable to process an obtained item. The JSON Number type is expected!");
            }
        }

        return null;
    }

    /**
     * Gets a value of the header {@code name} as a Date.
     * If not present, or not able to convert, returns NULL.
     *
     * @param name {@link String} header name to get a value for
     * @return {@link Date}
     */
    public Date getAsDate(String name) {
        String dateStr = getAsString(name);
        if (dateStr != null) {
            return RFC3339DateUtils.getDate(dateStr);
        }
        return null;
    }

    /**
     * Gets a value of the header {@code name} as a List of Json objects.
     * If not present, or not able to convert, returns NULL.
     *
     * @param name {@link String} header name to get a value for
     * @return a list of {@link JsonObjectWrapper}s
     */
    public List<JsonObjectWrapper> getAsList(String name) {
        JsonValue jsonValue = jsonObject.get(name);
        if (jsonValue == null) {
            // continue

        } else if (jsonValue instanceof JsonArray) {
            List<JsonValue> elements = ((JsonArray) jsonValue).getElements();
            if (elements != null && !elements.isEmpty()) {
                return elements.stream().map(this::toObject).collect(Collectors.toList());
            }

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to process an obtained item with value : '{}'. The JSON Array type is expected!", jsonValue);
            } else {
                LOG.warn("Unable to process an obtained item. The JSON Array type is expected!");
            }
        }

        return Collections.emptyList();
    }

}

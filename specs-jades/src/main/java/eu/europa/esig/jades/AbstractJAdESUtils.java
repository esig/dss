package eu.europa.esig.jades;

import eu.europa.esig.jws.AbstractJWSUtils;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class for JAdES signature validation against JSON schemas
 *
 */
public abstract class AbstractJAdESUtils extends AbstractJWSUtils {

    /** The RFC 7519 schema of definitions */
    protected static final String RFC7519_SCHEMA_LOCATION = "/schema/rfcs/rfc7519.json";

    /** The RFC 7519 schema name URI */
    protected static final String RFC7519_SCHEMA_URI = "rfc7519.json";

    /** The RFC 7797 schema of definitions */
    protected static final String RFC7797_SCHEMA_LOCATION = "/schema/rfcs/rfc7797.json";

    /** The RFC 7797 schema name URI */
    protected static final String RFC7797_SCHEMA_URI = "rfc7797.json";

    /** Subfolder with RFC definitions */
    protected static final String RFC_SUBDIRECTORY = "rfcs/";

    /** The JAdES schema name URI */
    protected static final String JAdES_SCHEMA_DEFINITIONS_URI = "19182-jsonSchema.json";

    /** The JAdES schema of definitions */
    protected static final String JAdES_SCHEMA_DEFINITIONS_LOCATION = "/schema/19182-jsonSchema.json";

    @Override
    public Map<URI, String> getRFCDefinitions() {
        final Map<URI, String> definitions = new HashMap<>();
        Map<URI, String> rfcDefinitions = super.getRFCDefinitions();
        for (Map.Entry<URI, String> entry : rfcDefinitions.entrySet()) {
            definitions.put(URI.create(RFC_SUBDIRECTORY + entry.getKey().toString()), entry.getValue());
        }
        definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7519_SCHEMA_URI), RFC7519_SCHEMA_LOCATION);
        definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7797_SCHEMA_URI), RFC7797_SCHEMA_LOCATION);
        return definitions;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.putAll(getRFCDefinitions());
        definitions.put(URI.create(JAdES_SCHEMA_DEFINITIONS_URI), JAdES_SCHEMA_DEFINITIONS_LOCATION);
        return definitions;
    }

}

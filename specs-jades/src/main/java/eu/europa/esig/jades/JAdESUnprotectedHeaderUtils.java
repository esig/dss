package eu.europa.esig.jades;

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JAdES Unprotected header validation against JSON schemas
 *
 */
public class JAdESUnprotectedHeaderUtils extends AbstractJAdESUtils {

    /** The unprotected header schema URI for a JAdES signature */
    private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_URI = "19182-unprotected-jsonSchema.json";

    /** The unprotected header schema for a JAdES signature */
    private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-unprotected-jsonSchema.json";

    /** Singleton instance */
    private static JAdESUnprotectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JAdESUnprotectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JAdESUnprotectedHeaderUtils}
     *
     * @return {@link JAdESUnprotectedHeaderUtils}
     */
    public static JAdESUnprotectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JAdESUnprotectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JAdES_UNPROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = super.getSchemaDefinitions();
        definitions.put(URI.create(JAdES_UNPROTECTED_HEADER_SCHEMA_URI), JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}

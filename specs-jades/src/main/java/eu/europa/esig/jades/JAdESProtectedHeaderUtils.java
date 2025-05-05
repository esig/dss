package eu.europa.esig.jades;

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JAdES Protected header validation against JSON schemas
 *
 */
public class JAdESProtectedHeaderUtils extends AbstractJAdESUtils {

    /** The protected header schema URI for a JAdES signature */
    private static final String JAdES_PROTECTED_HEADER_SCHEMA_URI = "19182-protected-jsonSchema.json";

    /** The protected header schema for a JAdES signature */
    private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-protected-jsonSchema.json";

    /** Singleton instance */
    private static JAdESProtectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JAdESProtectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JAdESProtectedHeaderUtils}
     *
     * @return {@link JAdESProtectedHeaderUtils}
     */
    public static JAdESProtectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JAdESProtectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JAdES_PROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = super.getSchemaDefinitions();
        definitions.put(URI.create(JAdES_PROTECTED_HEADER_SCHEMA_URI), JAdES_PROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}

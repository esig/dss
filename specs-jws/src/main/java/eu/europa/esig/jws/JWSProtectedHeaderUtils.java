package eu.europa.esig.jws;

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JWS Unprotected header validation against JSON schemas
 *
 */
public class JWSProtectedHeaderUtils extends AbstractJWSUtils {

    /** The protected header schema URI for a JWS signature */
    private static final String JWS_PROTECTED_HEADER_SCHEMA_URI = "rfc7515-protected.json";

    /** The protected header schema for a JWS signature */
    private static final String JWS_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-protected.json";

    /** Singleton instance */
    private static JWSProtectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JWSProtectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JWSProtectedHeaderUtils}
     *
     * @return {@link JWSProtectedHeaderUtils}
     */
    public static JWSProtectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JWSProtectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JWS_PROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.putAll(getRFCDefinitions());
        definitions.put(URI.create(JWS_PROTECTED_HEADER_SCHEMA_URI), JWS_PROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}

package eu.europa.esig.jws;

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JWS Unprotected header validation against JSON schemas
 *
 */
public class JWSUnprotectedHeaderUtils extends AbstractJWSUtils {

    /** The unprotected header schema URI for a JWS signature */
    private static final String JWS_UNPROTECTED_HEADER_SCHEMA_URI = "rfc7515-unprotected.json";

    /** The unprotected header schema for a JWS signature */
    private static final String JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-unprotected.json";

    /** Singleton instance */
    private static JWSUnprotectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JWSUnprotectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JWSUnprotectedHeaderUtils}
     *
     * @return {@link JWSUnprotectedHeaderUtils}
     */
    public static JWSUnprotectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JWSUnprotectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JWS_UNPROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.putAll(getRFCDefinitions());
        definitions.put(URI.create(JWS_UNPROTECTED_HEADER_SCHEMA_URI), JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}

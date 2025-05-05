package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.json.JSONSchemaAbstractUtils;

import java.net.URI;
import java.util.Map;

/**
 * This class contains utils for parsing and validation of the cryptographic suites according to
 * the ETSI TS 119 322 JSON schema
 *
 */
public final class CryptographicSuiteJsonUtils extends JSONSchemaAbstractUtils {

    /** Cryptographic suite schema URI */
    private static final String SCHEMA_URI = "http://uri.etsi.org/19322/algoCatSchema";

    /** Cryptographic suite schema's location */
    private static final String SCHEMA_LOCATION = "/schema/19322algocatjsonschema.json";

    /** Singleton instance */
    private static CryptographicSuiteJsonUtils singleton;

    /**
     * Empty constructor
     */
    private CryptographicSuiteJsonUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CryptographicSuiteJsonUtils}
     *
     * @return {@link CryptographicSuiteJsonUtils}
     */
    public static CryptographicSuiteJsonUtils getInstance() {
        if (singleton == null) {
            singleton = new CryptographicSuiteJsonUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.put(URI.create(SCHEMA_URI), SCHEMA_LOCATION);
        return definitions;
    }

}

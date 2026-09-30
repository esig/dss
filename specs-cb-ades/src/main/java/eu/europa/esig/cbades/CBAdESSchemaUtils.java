package eu.europa.esig.cbades;

import eu.europa.esig.cbor.CBORSchemaAbstractUtils;

/**
 * Utility class for verification of ETSI TS 119 152-1 CB-AdES signature structure
 *
 */
public class CBAdESSchemaUtils extends CBORSchemaAbstractUtils {

    /** The ETSI TS 119 152-1 CB-AdES schema URI */
    private static final String CB_AdES_SCHEMA_LOCATION = "/schema/19152-cborSchema.cddl";

    /** COSE_Messages element name, starting element for a COSE signature validation */
    public static final String COSE_MESSAGES = "COSE_Messages";

    /** COSE_Countersignature_start element name, starting element for a COSE counter signature validation */
    public static final String COSE_COUNTER_SIGNATURE = "COSE_Countersignature_start";

    /** Singleton instance */
    private static CBAdESSchemaUtils singleton;

    /**
     * Singleton
     */
    private CBAdESSchemaUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CBAdESSchemaUtils}
     *
     * @return {@link CBAdESSchemaUtils}
     */
    public static CBAdESSchemaUtils getInstance() {
        if (singleton == null) {
            singleton = new CBAdESSchemaUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaLocation() {
        return CB_AdES_SCHEMA_LOCATION;
    }

}

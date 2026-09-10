package eu.europa.esig.mdoc;

import eu.europa.esig.cbor.CBORSchemaAbstractUtils;

/**
 * Utility class for verification of ISO/IEC 18013-5 MobileSecurityObjectBytes structure.
 * NOTE: The class expects {@code MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)} as the input,
 *       unless overwritten.
 *
 */
public class MdocMobileSecurityObjectUtils extends CBORSchemaAbstractUtils {

    /** The MobileSecurityObject schema URI */
    private static final String MSO_SCHEMA_LOCATION = "/schema/iso_180135_mso.cddl";

    /** Represents the MobileSecurityObject element name */
    public static final String MOBILE_SECURITY_OBJECT = "MobileSecurityObject";

    /** Represents the MobileSecurityObjectBytes element name */
    public static final String MOBILE_SECURITY_OBJECT_BYTES = "MobileSecurityObjectBytes";

    /** Singleton instance */
    private static MdocMobileSecurityObjectUtils singleton;

    /**
     * Singleton
     */
    private MdocMobileSecurityObjectUtils() {
        // empty
    }

    /**
     * Returns instance of {@code MdocMobileSecurityObjectUtils}
     *
     * @return {@link MdocMobileSecurityObjectUtils}
     */
    public static MdocMobileSecurityObjectUtils getInstance() {
        if (singleton == null) {
            singleton = new MdocMobileSecurityObjectUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaLocation() {
        return MSO_SCHEMA_LOCATION;
    }

}

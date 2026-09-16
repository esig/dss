package eu.europa.esig.mdoc;

import eu.europa.esig.cbor.CBORSchemaAbstractUtils;

/**
 * Utility class for verification of ISO/IEC 18013-5 DeviceResponse structure
 *
 */
public class MdocDeviceResponseUtils extends CBORSchemaAbstractUtils {

    /** The ISO/IEC 18013-5 mdoc schema URI */
    private static final String MDOC_SCHEMA_LOCATION = "/schema/iso_180135_mdoc.cddl";

    /** Represents the DeviceResponse element name */
    public static final String DEVICE_RESPONSE = "DeviceResponse";

    /** Represents the Document element name */
    public static final String DOCUMENT = "Document";

    /** Represents the IssuerSigned element name */
    public static final String ISSUER_SIGNED = "IssuerSigned";

    /** Singleton instance */
    private static MdocDeviceResponseUtils singleton;

    /**
     * Singleton
     */
    private MdocDeviceResponseUtils() {
        // empty
    }

    /**
     * Returns instance of {@code MdocDeviceResponseUtils}
     *
     * @return {@link MdocDeviceResponseUtils}
     */
    public static MdocDeviceResponseUtils getInstance() {
        if (singleton == null) {
            singleton = new MdocDeviceResponseUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaLocation() {
        return MDOC_SCHEMA_LOCATION;
    }

}

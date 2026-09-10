package eu.europa.esig.mdoc;

import eu.europa.esig.cbor.CBORSchemaAbstractUtils;

/**
 * Utility class for verification of ISO/IEC 18013-5 SessionTranscript structure.
 *
 */
public class MdocSessionTranscriptUtils extends CBORSchemaAbstractUtils {

    /** The SessionTranscript schema URI */
    private static final String SESSION_TRANSCRIPT_SCHEMA_LOCATION = "/schema/iso_180135_sessionTranscript.cbor";

    /** Represents the SessionTranscript element name */
    public static final String SESSION_TRANSCRIPT = "SessionTranscript";

    /** Represents the SessionTranscriptBytes element name */
    public static final String SESSION_TRANSCRIPT_BYTES = "SessionTranscriptBytes";

    /** Singleton instance */
    private static MdocSessionTranscriptUtils singleton;

    /**
     * Singleton
     */
    private MdocSessionTranscriptUtils() {
        // empty
    }

    /**
     * Returns instance of {@code MdocSessionTranscriptUtils}
     *
     * @return {@link MdocSessionTranscriptUtils}
     */
    public static MdocSessionTranscriptUtils getInstance() {
        if (singleton == null) {
            singleton = new MdocSessionTranscriptUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaLocation() {
        return SESSION_TRANSCRIPT_SCHEMA_LOCATION;
    }

}
package eu.europa.esig.dss.evidencerecord.common.validation;

/**
 * Defines CryptographicInformation element content
 */
public class CryptographicInformation implements EvidenceRecordObject {

    private static final long serialVersionUID = -3444524343827820741L;

    /** Defines content of the Cryptographic Information element */
    private final byte[] content;

    /** Defines type of the Cryptographic Information element */
    private final CryptographicInformationType type;

    /**
     * Default constructor
     *
     * @param content byte array containing Cryptographic Information element's content
     * @param type {@link CryptographicInformationType}
     */
    public CryptographicInformation(final byte[] content, final CryptographicInformationType type) {
        this.content = content;
        this.type = type;
    }

    /**
     * Gets content of the Cryptographic Information element
     *
     * @return byte array
     */
    public byte[] getContent() {
        return content;
    }

    /**
     * Gets type of the Cryptographic Information element
     *
     * @return {@link CryptographicInformationType}
     */
    public CryptographicInformationType getType() {
        return type;
    }

}

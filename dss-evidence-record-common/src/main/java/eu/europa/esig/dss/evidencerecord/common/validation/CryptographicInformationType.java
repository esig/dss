package eu.europa.esig.dss.evidencerecord.common.validation;

import java.util.Objects;

/**
 * Defines type of the cryptographic information content
 */
public enum CryptographicInformationType {

    /**
     * For type CRL, a base64 encoding of a DER-encoded X.509 CRL[RFC5280]
     */
    CRL("CRL"),

    /**
     * For type OCSP, a base64 encoding of a DER-encoded OCSPResponse
     */
    OCSP("OCSP"),

    /**
     * For type SCVP, a base64 encoding of a DER-encoded CVResponse;
     */
    SCVP("SCVP"),

    /**
     * For type CERT, a base64 encoding of a DER-encoded X.509 certificate [RFC5280]
     */
    CERT("CERT");

    /** Identifies type definition string */
    private final String label;

    /**
     * Default constructor
     *
     * @param label {@link String}
     */
    CryptographicInformationType(final String label) {
        this.label = label;
    }

    /**
     * Gets the type definition label
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Returns {@code CryptographicInformationType} for the given label String
     *
     * @param label {@link String}
     * @return {@link CryptographicInformationType}
     */
    public static CryptographicInformationType fromLabel(String label) {
        Objects.requireNonNull(label, "Label shall be provided!");
        for (CryptographicInformationType type : values()) {
            if (label.equals(type.label)) {
                return type;
            }
        }
        return null;
    }

}

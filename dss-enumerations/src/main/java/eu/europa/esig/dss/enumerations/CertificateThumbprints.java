package eu.europa.esig.dss.enumerations;

/**
 * Enumeration defining options to embed the certificate thumbprints header into a signature
 * NOTE: Used in CB-AdES
 *
 */
public enum CertificateThumbprints {

    /**
     * Incorporates signing certificate thumbprint within the 'x5t' header parameter.
     */
    SIGNING_CERTIFICATE,

    /**
     * Incorporates certificate chain thumbprints within the 'x5ts' header parameter.
     */
    CERTIFICATE_CHAIN,

    /**
     * Does not create 'x5t' nor 'x5ts' header parameter.
     */
    NONE

}

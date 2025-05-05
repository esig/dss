package eu.europa.esig.dss.enumerations;

/**
 * Represents a validation model of a certificate chain (e.g. SHELL, CHAIN, etc.)
 *
 */
public enum ValidationModel {

    /**
     * Model for validation of X.509 certificate chains where all certificates have to be valid at a given time
     */
    SHELL,

    /**
     * Model for validation of X.509 certificate chains where all CA certificates have to be valid at the time they
     * were used for issuing a certificate and the end-entity certificate was valid when creating the signature
     */
    CHAIN,

    /**
     * Hybrid validation model, evaluating the signing-certificate at the validation time,
     * while all other intermediate CA certificates at the time of the signing-certificate's issuance
     */
    HYBRID

}

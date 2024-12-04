package eu.europa.esig.dss.enumerations;

/**
 * This list contains enumerations for definition of a type of validation data container to be used
 * on signature augmentation (such as -LT level or -LTA-LT)
 * NOTE: Currently the applicability of the enumeration is limited to XAdES and JAdES signature formats
 *
 */
public enum ValidationDataEncapsulationStrategy {

    /**
     * This constraint defines a "classic" augmentation approach used in old versions of DSS, with:
     * - LT-level validation data is being included within corresponding CertificateValues/RevocationValues elements;
     * - LTA-LT level validation data is being added within TimeStampValidationData element,
     *   containing both the missing validation data for the signature and timestamps, intermixed.
     * NOTE: this method should not be used for any but legacy applications.
     */
    CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA,

    /**
     * This constraint defines an augmentation approach without using AnyValidationData element, where:
     * - LT-level validation data for a signature is being included within corresponding
     *   CertificateValues/RevocationValues elements, while the validation data for incorporated time-stamps is
     *   included within TimeStampValidationData element;
     * - LTA-LT level validation data is being added within TimeStampValidationData element,
     *   containing both the missing validation data for the signature and timestamps, intermixed.
     */
    CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED,

    /**
     * This constraint defines a complete augmentation approach compliant with ETSI EN 319 132-1 v1.3.1, where:
     * - LT-level validation data for a signature is being included within corresponding
     *   CertificateValues/RevocationValues elements, while the validation data for incorporated time-stamps is
     *   included within TimeStampValidationData element;
     * - LTA-LT level validation data for timestamps is being added within TimeStampValidationData element,
     *   while the missing validation information for the signature is being included within the AnyValidationData element.
     */
    CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA,

    /**
     * This constraint defines an augmentation approach compliant with ETSI EN 319 132-1 v1.3.1, where:
     * - LT-level validation data for a signature is being included within corresponding
     *   CertificateValues/RevocationValues elements, while the validation data for incorporated time-stamps is
     *   included within AnyValidationData element;
     * - LTA-LT level validation data is being added within AnyValidationData element,
     *   containing both the missing validation data for the signature and timestamps, intermixed.
     */
    CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA,

    /**
     * This constraint defines an augmentation approach compliant with ETSI EN 319 132-1 v1.3.1, where:
     * - LT-level validation data is being included within the AnyValidationData element;
     * - LTA-LT level validation data is being added within AnyValidationData element,
     *   containing both the missing validation data for the signature and timestamps, intermixed.
     */
    ANY_VALIDATION_DATA_ONLY

}

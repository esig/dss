package eu.europa.esig.dss.enumerations;

/**
 * Defines the origin of an Evidence Record
 */
public enum EvidenceRecordOrigin {

    /** Defines an evidence record extracted from an ASiC container */
    CONTAINER,

    /** Defines an evidence record embedded in electronic signature */
    EMBEDDED,

    /** An evidence record provided externally to the validation */
    EXTERNAL

}

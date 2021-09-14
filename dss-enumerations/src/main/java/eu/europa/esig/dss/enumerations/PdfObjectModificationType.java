package eu.europa.esig.dss.enumerations;

/**
 * Specifies a modification origin kind
 *
 */
public enum PdfObjectModificationType {

    /** Represents an object addition to a final revision */
    CREATION,

    /** Represents an object deletion from a final revision */
    DELETION,

    /** Represents an object change in a final revision */
    MODIFICATION;

}

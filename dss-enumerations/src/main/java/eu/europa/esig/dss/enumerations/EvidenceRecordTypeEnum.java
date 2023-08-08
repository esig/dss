package eu.europa.esig.dss.enumerations;

import java.util.Objects;

/**
 * Defines supported Evidence Record types
 *
 */
public enum EvidenceRecordTypeEnum {

    /** An XML Evidence Record according to RFC 6283 */
    XML_EVIDENCE_RECORD("XML Evidence Record"),

    /** An XML Evidence Record according to RFC 4998 */
    ASN1_EVIDENCE_RECORD("ASN.1 Evidence Record");

    /** User-friendly descriptor of the evidence record type */
    private final String label;

    /**
     * Default constructor
     *
     * @param label {@link String}
     */
    EvidenceRecordTypeEnum(String label) {
        this.label = label;
    }

    /**
     * Gets a user-friendly descriptor of an evidence record type
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an {@code EvidenceRecordEnum} for the given {@code label} string value
     *
     * @param label {@link String} representing a user-friendly identifier for an evidence record
     * @return {@link EvidenceRecordTypeEnum}
     */
    public static EvidenceRecordTypeEnum fromLabel(String label) {
        Objects.requireNonNull(label, "Label cannot be null!");
        for (EvidenceRecordTypeEnum evidenceRecordEnum : EvidenceRecordTypeEnum.values()) {
            if (label.equals(evidenceRecordEnum.label)) {
                return evidenceRecordEnum;
            }
        }
        throw new UnsupportedOperationException(String.format("Evidence record of type '%s' is not supported!", label));
    }

}

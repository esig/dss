package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum}
 *
 */
public class EvidenceRecordTypeEnumParser {

    /**
     * Empty constructor
     */
    private EvidenceRecordTypeEnumParser() {
        // empty
    }

    /**
     * Parses the label value and returns {@code EvidenceRecordEnum}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordTypeEnum}
     */
    public static EvidenceRecordTypeEnum parse(String v) {
        if (v != null) {
            return EvidenceRecordTypeEnum.fromLabel(v);
        }
        return null;
    }

    /**
     * Gets a user-friendly label value for the evidence record type
     *
     * @param v {@link EvidenceRecordTypeEnum}
     * @return {@link String}
     */
    public static String print(EvidenceRecordTypeEnum v) {
        if (v != null) {
            return v.getLabel();
        }
        return null;
    }

}

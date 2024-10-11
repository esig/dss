package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.EvidenceRecordOrigin}
 *
 */
public class EvidenceRecordOriginParser {

    /**
     * Empty constructor
     */
    private EvidenceRecordOriginParser() {
        // empty
    }

    /**
     * Parses the label value and returns {@code EvidenceRecordOrigin}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordOrigin}
     */
    public static EvidenceRecordOrigin parse(String v) {
        if (v != null) {
            return EvidenceRecordOrigin.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a user-friendly label value for the evidence record origin
     *
     * @param v {@link EvidenceRecordOrigin}
     * @return {@link String}
     */
    public static String print(EvidenceRecordOrigin v) {
        if (v != null) {
            return v.name();
        }
        return null;
    }

}

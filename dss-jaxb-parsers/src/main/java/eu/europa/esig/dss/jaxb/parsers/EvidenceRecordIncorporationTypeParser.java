package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType}
 *
 */
public class EvidenceRecordIncorporationTypeParser {

    /**
     * Empty constructor
     */
    private EvidenceRecordIncorporationTypeParser() {
        // empty
    }

    /**
     * Parses the label value and returns {@code EvidenceRecordIncorporationType}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordIncorporationType}
     */
    public static EvidenceRecordIncorporationType parse(String v) {
        if (v != null) {
            return EvidenceRecordIncorporationType.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a user-friendly label value for the evidence record origin
     *
     * @param v {@link EvidenceRecordIncorporationType}
     * @return {@link String}
     */
    public static String print(EvidenceRecordIncorporationType v) {
        if (v != null) {
            return v.name();
        }
        return null;
    }

}

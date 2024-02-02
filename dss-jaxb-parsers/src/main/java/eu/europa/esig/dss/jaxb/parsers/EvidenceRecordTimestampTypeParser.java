package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;

/**
 * Parses the {@code eu.europa.esig.dss.jaxb.parsers.EvidenceRecordTimestampTypeParser}
 *
 */
public class EvidenceRecordTimestampTypeParser {

    private EvidenceRecordTimestampTypeParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code EvidenceRecordTimestampType}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordTimestampType}
     */
    public static EvidenceRecordTimestampType parse(String v) {
        return EvidenceRecordTimestampType.valueOf(v);
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link EvidenceRecordTimestampType}
     * @return {@link String}
     */
    public static String print(EvidenceRecordTimestampType v) {
        return v.name();
    }

}

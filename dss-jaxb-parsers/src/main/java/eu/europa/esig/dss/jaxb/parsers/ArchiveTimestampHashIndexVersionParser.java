package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;

/**
 * Parses the {@code ArchiveTimestampHashIndexVersion}
 *
 */
public class ArchiveTimestampHashIndexVersionParser {

    /**
     * Default constructor
     */
    private ArchiveTimestampHashIndexVersionParser() {
        // empty
    }

    /**
     * Parses the label value and returns {@code ArchiveTimeStampHashIndexVersion}
     *
     * @param v {@link String} to parse
     * @return {@link ArchiveTimestampHashIndexVersion}
     */
    public static ArchiveTimestampHashIndexVersion parse(String v) {
        if (v != null) {
            return ArchiveTimestampHashIndexVersion.forLabel(v);
        }
        return null;
    }

    /**
     * Gets a user-friendly text label name of the value
     *
     * @param v {@link ArchiveTimestampHashIndexVersion}
     * @return {@link String}
     */
    public static String print(ArchiveTimestampHashIndexVersion v) {
        if (v != null) {
            return v.getLabel();
        }
        return null;
    }

}

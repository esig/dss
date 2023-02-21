package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.GeneralNameType;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.GeneralNameType}
 *
 */
public class GeneralNameTypeParser {

    /**
     * Default constructor
     */
    private GeneralNameTypeParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code GeneralNameType}
     *
     * @param v {@link String} to parse
     * @return {@link GeneralNameType}
     */
    public static GeneralNameType parse(String v) {
        if (v != null) {
            return GeneralNameType.fromLabel(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link GeneralNameType}
     * @return {@link String}
     */
    public static String print(GeneralNameType v) {
        if (v != null) {
            return v.getLabel();
        }
        return null;
    }

}

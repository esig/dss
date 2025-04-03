package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.Level;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.Level}
 *
 */
public class LevelParser {

    /**
     * Default constructor
     */
    private LevelParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code Level}
     *
     * @param v {@link String} to parse
     * @return {@link Level}
     */
    public static Level parse(String v) {
        if (v != null) {
            return Level.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link Level}
     * @return {@link String}
     */
    public static String print(Level v) {
        if (v != null) {
            return v.toString();
        }
        return null;
    }

}

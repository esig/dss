package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.ValidationModel;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.ValidationModel}
 *
 */
public class ValidationModelParser {

    /**
     * Default constructor
     */
    private ValidationModelParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code ValidationModel}
     *
     * @param v {@link String} to parse
     * @return {@link ValidationModel}
     */
    public static ValidationModel parse(String v) {
        if (v != null) {
            return ValidationModel.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link ValidationModel}
     * @return {@link String}
     */
    public static String print(ValidationModel v) {
        if (v != null) {
            return v.toString();
        }
        return null;
    }

}

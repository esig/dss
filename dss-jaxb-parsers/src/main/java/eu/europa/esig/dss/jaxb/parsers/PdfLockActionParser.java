package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.PdfLockAction;

/**
 * Parses a {@code PdfLockAction}
 *
 */
public class PdfLockActionParser {

    /**
     * Default constructor
     */
    private PdfLockActionParser() {
    }

    /**
     * Parses the value and returns {@code PdfObjectModificationType}
     *
     * @param v {@link String} to parse
     * @return {@link eu.europa.esig.dss.enumerations.PdfLockAction}
     */
    public static PdfLockAction parse(String v) {
        return PdfLockAction.valueOf(v);
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link PdfLockAction}
     * @return {@link String}
     */
    public static String print(PdfLockAction v) {
        return v.toString();
    }

}

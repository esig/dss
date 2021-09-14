package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;

/**
 * Parses a {@code PdfObjectModificationType}
 *
 */
public class PdfObjectModificationTypeParser {

    /**
     * Default constructor
     */
    private PdfObjectModificationTypeParser() {
    }

    /**
     * Parses the value and returns {@code PdfObjectModificationType}
     *
     * @param v {@link String} to parse
     * @return {@link eu.europa.esig.dss.enumerations.PdfObjectModificationType}
     */
    public static PdfObjectModificationType parse(String v) {
        return PdfObjectModificationType.valueOf(v);
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link PdfObjectModificationType}
     * @return {@link String}
     */
    public static String print(PdfObjectModificationType v) {
        return v.toString();
    }

}

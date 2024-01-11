package eu.europa.esig.dss.pdf;

/**
 * Represents a PDF internal object
 *
 */
public interface PdfObject {

    /**
     * Gets value of the PDF object
     *
     * @return {@link Object}
     */
    Object getValue();

    /**
     * Returns parent of the current PdfObject if applicable
     *
     * @return {@link PdfObject}
     */
    PdfObject getParent();

}

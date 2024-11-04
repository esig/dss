package eu.europa.esig.dss.pades.validation;

/**
 * Represents a PDF object identifier within a PDF document
 *
 */
public interface PdfObjectKey {

    /**
     * Gets the format specific object reference value
     *
     * @return implementation specific object reference value
     */
    Object getValue();

    /**
     * Gets object's key number
     *
     * @return long value of the object's key
     */
    long getNumber();

    /**
     * Gets generation of the Pdf object
     *
     * @return int generation number value
     */
    int getGeneration();

}

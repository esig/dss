package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pdf.PdfDocumentReader;

/**
 * This class is used to find and return all object modifications occurred between two PDF document revisions.
 *
 */
public interface PdfObjectModificationsFinder {

    /**
     * Returns found and categorized object modifications occurred between {@code originalRevisionReader}
     * and {@code finalRevisionReader}.
     *
     * @param originalRevisionReader {@link PdfDocumentReader} representing original (e.g. signed) PDF revision
     * @param finalRevisionReader {@link PdfDocumentReader} representing the final PDF document revision
     * @return {@link PdfObjectModifications} found between two given revisions
     */
    PdfObjectModifications find(final PdfDocumentReader originalRevisionReader, final PdfDocumentReader finalRevisionReader);

}

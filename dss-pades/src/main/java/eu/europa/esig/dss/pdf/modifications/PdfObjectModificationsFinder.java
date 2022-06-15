package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pdf.PdfDocumentReader;

import java.util.Set;

/**
 * This class is used to find and return all object modifications occurred between two PDF document revisions.
 *
 */
public interface PdfObjectModificationsFinder {

    /**
     * Returns a set of found object modifications occurred between {@code originalRevisionReader}
     * and {@code finalRevisionReader}.
     *
     * @param originalRevisionReader {@link PdfDocumentReader} representing original (e.g. signed) PDF revision
     * @param finalRevisionReader {@link PdfDocumentReader} representing the final PDF document revision
     * @return a set of {@link ObjectModification}s between two given revisions
     */
    Set<ObjectModification> find(final PdfDocumentReader originalRevisionReader, final PdfDocumentReader finalRevisionReader);

}

package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface contains method for verification of a document on a conformance to a ZIP or ASiC format
 * NOTE: sometimes it is required to accept simple ZIP archive, but reject ASiC container of a different
 *       implementation (i.e. XAdES vs CAdES), that is why we implement two methods.
 *
 */
public interface ASiCFormatDetector {

    /**
     * Verifies whether the {@code document} is a supported ZIP container by the current implementation
     *
     * @param document {@link DSSDocument} to be analyzed
     * @return TRUE if the document is a supported ZIP container, FALSE otherwise
     */
    boolean isSupportedZip(DSSDocument document);

    /**
     * Verifies whether the {@code document} is a supported ASiC container by the current implementation
     *
     * @param document {@link DSSDocument} to be analyzed
     * @return TRUE if the document is a supported ASiC container, FALSE otherwise
     */
    boolean isSupportedASiC(DSSDocument document);

    /**
     * Verifies whether the {@code asicContent} is a supported ZIP container by the current implementation
     *
     * @param asicContent {@link ASiCContent} to be analyzed
     * @return TRUE if the ASiCContent is a supported ZIP container, FALSE otherwise
     */
    boolean isSupportedZip(ASiCContent asicContent);

    /**
     * Verifies whether the {@code asicContent} is a supported ASiC container by the current implementation
     *
     * @param asicContent {@link ASiCContent} to be analyzed
     * @return TRUE if the ASiCContent is a supported ASiC container, FALSE otherwise
     */
    boolean isSupportedASiC(ASiCContent asicContent);

}

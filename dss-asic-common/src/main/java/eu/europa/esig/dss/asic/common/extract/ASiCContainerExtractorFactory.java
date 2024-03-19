package eu.europa.esig.dss.asic.common.extract;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to find and load a corresponding implementation of
 * {@code eu.europa.esig.dss.asic.common.extractor.ASiCContainerExtractor} for the given
 * {@code eu.europa.esig.dss.model.DSSDocument} ASiC archive
 *
 */
public interface ASiCContainerExtractorFactory {

    /**
     * Returns whether the format of given ASiC document is supported by the current {@code ASiCContainerExtractor}
     *
     * @param asicContainer {@link DSSDocument}, which content should be extracted
     * @return TRUE if the document is supported by the current implementation, FALSE otherwise
     */
    boolean isSupported(DSSDocument asicContainer);

    /**
     * Creates a new {@code ASiCContainerExtractor} for the given ZIP-archive container
     *
     * @param asicContainer {@link DSSDocument}, representing a ZIP-containers to be extracted
     * @return {@link ASiCContainerExtractor} to be used to extract content of the ASiC container
     */
    ASiCContainerExtractor create(DSSDocument asicContainer);

}

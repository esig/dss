package eu.europa.esig.dss.asic.common.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * Extracts documents from a provided ZIP archive and produces a {@code eu.europa.esig.dss.asic.common.ASiCContent},
 * containing the representation of the archive's content
 *
 */
public interface ASiCContainerExtractor {

    /**
     * Extracts a content (documents) embedded into the {@code asicContainer}
     *
     * @return {@link ASiCContent}
     */
    ASiCContent extract();

}

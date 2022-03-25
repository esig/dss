package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load relevant {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * for given {@code eu.europa.esig.dss.model.DSSDocument} containers or
 * {@code eu.europa.esig.dss.asic.common.ASiCContent}s
 *
 */
public interface ASiCContainerMergerFactory {

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param containers {@link DSSDocument}s to be merged
     * @return TRUE if both documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument... containers);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given ZIP-archive containers
     *
     * @param containers {@link DSSDocument}s representing ZIP-containers to be merged
     * @return {@link DSSDocument} representing a merge result of two given ZIP-containers
     */
    ASiCContainerMerger create(DSSDocument... containers);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContents {@link ASiCContent}s to be merged
     * @return TRUE if both containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent... asicContents);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s representing content of ZIP-containers to be merged
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContainerMerger create(ASiCContent... asicContents);

}

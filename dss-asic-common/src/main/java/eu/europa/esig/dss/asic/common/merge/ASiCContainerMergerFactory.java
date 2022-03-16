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
     * @param containerOne {@link DSSDocument}
     * @param containerTwo {@link DSSDocument}
     * @return TRUE if both documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument containerOne, DSSDocument containerTwo);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given ZIP-archive containers
     *
     * @param containerOne {@link DSSDocument} representing a first ZIP-container to be merged
     * @param containerTwo {@link DSSDocument} representing a second ZIP-container to be merged
     * @return {@link DSSDocument} representing a merge result of two given ZIP-containers
     */
    ASiCContainerMerger create(DSSDocument containerOne, DSSDocument containerTwo);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContentOne {@link ASiCContent}
     * @param asicContentTwo {@link ASiCContent}
     * @return TRUE if both containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent asicContentOne, ASiCContent asicContentTwo);

    /**
     * Creates a new {@code ASiCContainerMerger} for the given {@code ASiCContent}s
     *
     * @param contentOne {@link ASiCContent} representing a content of first ZIP-container to be merged
     * @param contentTwo {@link ASiCContent} representing a content of second ZIP-container to be merged
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContainerMerger create(ASiCContent contentOne, ASiCContent contentTwo);

}

package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to verify a possibility to merge two ASiC containers and
 * merge them in a single container, when possible.
 *
 */
public interface ASiCContainerMerger {

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param containerOne {@link DSSDocument}
     * @param containerTwo {@link DSSDocument}
     * @return TRUE if both documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument containerOne, DSSDocument containerTwo);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContentOne {@link ASiCContent}
     * @param asicContentTwo {@link ASiCContent}
     * @return TRUE if both containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent asicContentOne, ASiCContent asicContentTwo);

    /**
     * Merges two given containers to a new one, if possible
     *
     * @return {@link DSSDocument} representing a merge result of two given ZIP-containers
     */
    DSSDocument merge();

    /**
     * Merges two given containers to a single {@code ASiCContent}, if possible
     *
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContent mergeToASiCContent();

}

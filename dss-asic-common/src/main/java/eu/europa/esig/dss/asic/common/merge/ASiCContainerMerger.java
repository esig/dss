package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to verify a possibility to merge ASiC containers and
 * merge them in a single container, when possible.
 *
 */
public interface ASiCContainerMerger {

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param containers {@link DSSDocument}s to be merged
     * @return TRUE if all documents are supported by the current container, FALSE otherwise
     */
    boolean isSupported(DSSDocument... containers);

    /**
     * Returns whether the format of given containers is supported by the current {@code ASiCContainerMerger}
     *
     * @param asicContents {@link ASiCContent}s to be merged
     * @return TRUE if all containers are supported by the current container, FALSE otherwise
     */
    boolean isSupported(ASiCContent... asicContents);

    /**
     * Merges given containers to a new container document, when possible
     *
     * @return {@link DSSDocument} representing a merge result of the given ZIP-containers
     */
    DSSDocument merge();

    /**
     * Merges given containers to a single {@code ASiCContent}, when possible
     *
     * @return {@link ASiCContent} representing a merge result
     */
    ASiCContent mergeToASiCContent();

}

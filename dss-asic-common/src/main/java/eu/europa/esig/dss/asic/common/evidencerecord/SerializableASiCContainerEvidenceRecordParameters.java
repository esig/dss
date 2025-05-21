package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.enumerations.ASiCContainerType;

import java.io.Serializable;

/**
 * Interface for definition of parameters for an ASiC container generation with an evidence record document
 *
 */
public interface SerializableASiCContainerEvidenceRecordParameters extends Serializable {

    /**
     * Gets the target container type
     *
     * @return {@link ASiCContainerType}
     */
    ASiCContainerType getContainerType();

}

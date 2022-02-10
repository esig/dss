package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Contains metadata for a ZIP-container entry
 *
 */
public interface DSSZipEntryDocument extends DSSDocument {

    /**
     * Returns ZIP entry wrapper containing metadata about a file within a ZIP-container
     *
     * @return {@link DSSZipEntry}
     */
    DSSZipEntry getZipEntry();

}

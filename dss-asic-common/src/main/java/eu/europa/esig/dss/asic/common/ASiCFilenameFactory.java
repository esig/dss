package eu.europa.esig.dss.asic.common;

import java.io.Serializable;

/**
 * This interface is used to provide filenames for newly created ZIP-entries
 * during a signature creation or extension for ASiC containers.
 *
 * NOTE: Names of signature or manifest files shall be defined with leading "META-INF/" string,
 * specifying the target folder of the signature file within a container.
 *
 * As the same factory is used for ASiC-S and ASiC-E container types,
 * it shall implement logic for both container types, when applicable.
 * The type of the container can be obtained from {@code asicContent.getContainerType()} method.
 *
 */
public interface ASiCFilenameFactory extends Serializable {

    /**
     * Returns a filename for a signature file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} signature filename
     */
    String getSignatureFilename(ASiCContent asicContent);

    /**
     * Returns a filename of a manifest file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} manifest filename
     */
    String getManifestFilename(ASiCContent asicContent);

    /**
     * Returns a name of a ZIP archive containing signed documents in case of an ASiC-E signature, when applicable
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} data package filename
     */
    String getDataPackageFilename(ASiCContent asicContent);

}

/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * This interface is used to provide filenames for newly created ZIP-entries
 * during a signature creation or extension for an ASiC with CAdES containers.
 *
 * NOTE: Names of signature, timestamp or manifest files shall be defined with leading "META-INF/" string,
 * specifying the target folder of the signature file within a container.
 *
 * As the same factory is used for ASiC-S and ASiC-E container types,
 * it shall implement logic for both container types, when applicable.
 * The type of the container can be obtained from {@code asicContent.getContainerType()} method.
 *
 */
public interface ASiCWithCAdESFilenameFactory {

    /**
     * Returns a filename for a signature file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} signature filename
     */
    String getSignatureFilename(ASiCContent asicContent);

    /**
     * Returns a filename for a timestamp file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} timestamp filename
     */
    String getTimestampFilename(ASiCContent asicContent);

    /**
     * Returns a filename of a manifest file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} manifest filename
     */
    String getManifestFilename(ASiCContent asicContent);

    /**
     * Returns a new filename of an archive manifest file to be moved.
     *
     * NOTE: ASiC-E with CAdES shall always create a new archive manifest with the same name,
     *       while moving the last existing archive manifest.
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} manifest filename
     */
    String getArchiveManifestFilename(ASiCContent asicContent);

    /**
     * Returns a name of a ZIP archive containing signed documents in case of an ASiC-E signature, when applicable
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} data package filename
     */
    String getDataPackageFilename(ASiCContent asicContent);

}

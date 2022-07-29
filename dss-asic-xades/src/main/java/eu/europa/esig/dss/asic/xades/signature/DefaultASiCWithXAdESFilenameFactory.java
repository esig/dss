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
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCFilenameFactory;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

/**
 * This class provides a default implementation of {@code ASiCWithXAdESFilenameFactory}
 * used within basic configuration of DSS for creation of filenames for new container entries.
 *
 */
public class DefaultASiCWithXAdESFilenameFactory extends AbstractASiCFilenameFactory implements ASiCWithXAdESFilenameFactory {

    private static final long serialVersionUID = -3252975270136045191L;

    /**
     * Default constructor
     */
    public DefaultASiCWithXAdESFilenameFactory() {
    }

    @Override
    public String getSignatureFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            return ASiCUtils.SIGNATURES_XML; // "META-INF/signatures.xml"

        } else if (ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument())) {
            return ASiCUtils.OPEN_DOCUMENT_SIGNATURES; // "META-INF/documentsignatures.xml"

        } else { // ASiC-E
            List<String> existingSignatureNames = DSSUtils.getDocumentNames(asicContent.getSignatureDocuments());
            // "META-INF/signatures*.xml"
            return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_XADES_SIGNATURE, existingSignatureNames);
        }
    }

    @Override
    public String getManifestFilename(ASiCContent asicContent) {
        return ASiCUtils.ASICE_METAINF_MANIFEST; // "META-INF/manifest.xml"
    }

    @Override
    public String getDataPackageFilename(ASiCContent asicContent) {
        return ASiCUtils.PACKAGE_ZIP; // "package.zip"
    }

}

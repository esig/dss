/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCDataToSignHelperBuilder;
import eu.europa.esig.dss.utils.Utils;

/**
 * Contains common method for getDataToSign preparation for an ASiC with CAdES container signature
 *
 */
public abstract class AbstractASiCWithCAdESDataToSignHelperBuilder extends AbstractASiCDataToSignHelperBuilder {

    /**
     * Defines rules for filename creation for new manifest files.
     */
    protected final ASiCWithCAdESFilenameFactory asicFilenameFactory;

    /**
     * Default constructor
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    protected AbstractASiCWithCAdESDataToSignHelperBuilder(final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        this.asicFilenameFactory = asicFilenameFactory;
    }

    /**
     * Gets whether the ASiC represents an existing archive
     *
     * @param asicContent {@link ASiCContent}
     * @return TRUE if the ASiCContent is an existing ASiC archive, FALSE otherwise
     */
    protected boolean isASiCArchive(ASiCContent asicContent) {
        return Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())
                || Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())
                || Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments());
    }

    @Override
    protected String getDataPackageName(ASiCContent asicContent) {
        return asicFilenameFactory.getDataPackageFilename(asicContent);
    }

}

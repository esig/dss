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
package eu.europa.esig.dss.asic.cades.signature.manifest;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;

/**
 * This class is used to create a Manifest file for a timestamp creation
 *
 */
public class ASiCWithCAdESTimestampManifestBuilder extends ASiCEWithCAdESManifestBuilder {

    /**
     * The default constructor
     *
     * @param asicContent       {@link ASiCContent} representing container's document structure
     * @param digestAlgorithm   {@link DigestAlgorithm} to use for reference digest computation
     * @param timestampFilename {@link String} filename of the time-stamp document associated with the manifest
     */
    public ASiCWithCAdESTimestampManifestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm,
                                                 final String timestampFilename) {
        super(asicContent, timestampFilename, digestAlgorithm);
    }

    /**
     * Constructor with filename factory
     *
     * @param asicContent {@link ASiCContent} representing container's document structure
     * @param timestampFilename {@link String} filename of the time-stamp document associated with the manifest
     * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public ASiCWithCAdESTimestampManifestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm,
            final String timestampFilename, final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        super(asicContent, timestampFilename, digestAlgorithm, asicFilenameFactory);
    }

    @Override
    protected MimeType getSigReferenceMimeType() {
        return MimeTypeEnum.TST;
    }

    @Override
    public ASiCWithCAdESTimestampManifestBuilder setAsicContentDocumentFilter(ASiCContentDocumentFilter asicContentDocumentFilter) {
        return (ASiCWithCAdESTimestampManifestBuilder) super.setAsicContentDocumentFilter(asicContentDocumentFilter);
    }

}

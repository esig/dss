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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCWithCAdESSignatureManifestBuilder;
import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * Builds a {@code GetDataToSignASiCWithCAdESHelper} for a signature creation
 *
 */
public class ASiCWithCAdESSignatureDataToSignHelperBuilder extends ASiCWithCAdESDataToSignHelperBuilder {

    /**
     * Default constructor
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public ASiCWithCAdESSignatureDataToSignHelperBuilder(final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        super(asicFilenameFactory);
    }

    @Override
    protected ASiCEWithCAdESManifestBuilder getManifestBuilder(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
        // Required as a part of the created manifest file
        String signatureFilename = asicFilenameFactory.getSignatureFilename(asicContent);
        return new ASiCWithCAdESSignatureManifestBuilder(asicContent, parameters.getDigestAlgorithm(), signatureFilename, asicFilenameFactory);
    }

}

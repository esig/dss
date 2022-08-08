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
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a {@code GetDataToSignASiCWithCAdESHelper} for a signature creation
 *
 */
public class ASiCWithCAdESSignatureDataToSignHelperBuilder extends ASiCWithCAdESDataToSignHelperBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESSignatureDataToSignHelperBuilder.class);

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
        String signatureFilename = getSignatureFilename(parameters.aSiC(), asicContent);
        return new ASiCWithCAdESSignatureManifestBuilder(asicContent, parameters.getDigestAlgorithm(), signatureFilename, asicFilenameFactory);
    }

    /**
     * NOTE: Temporary method to allow migration from parameters.aSiC().setSignatureFilename(filename)
     * to ASiCWithXAdESFilenameFactory
     *
     * @return {@link String} filename
     */
    private String getSignatureFilename(ASiCParameters asicParameters, ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(asicParameters.getSignatureFileName())) {
            LOG.warn("The signature filename has been defined within deprecated method parameters.aSiC().setSignatureFilename(filename). " +
                    "Please use asicWithCAdESService.setAsicFilenameFactory(asicFilenameFactory) defining a custom filename factory.");
            return asicParameters.getSignatureFileName();
        }
        return asicFilenameFactory.getSignatureFilename(asicContent);
    }

}

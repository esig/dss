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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractGetDataToSignHelper;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * An abstract class to generate a DataToSign with ASiC-E with XAdES
 */
public class DataToSignASiCEWithXAdESHelper extends AbstractGetDataToSignHelper implements GetDataToSignASiCWithXAdESHelper {

    /** The default signature filename */
    private static final String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = ASiCUtils.META_INF_FOLDER + "signatures001.xml";

    /** ASiC Container creation parameters */
    private final ASiCParameters asicParameters;

    /**
     * The default constructor
     *
     * @param asicContent {@link ASiCContent}
     * @param asicParameters {@link ASiCParameters}
     */
    public DataToSignASiCEWithXAdESHelper(final ASiCContent asicContent, final ASiCParameters asicParameters) {
        super(asicContent);
        this.asicParameters = asicParameters;
    }

    @Override
    public List<DSSDocument> getToBeSigned() {
        return asicContent.getSignedDocuments();
    }

    @Override
    public String getSignatureFilename() {
        if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
            return ASiCUtils.META_INF_FOLDER + asicParameters.getSignatureFileName();
        }
        List<DSSDocument>existingSignatures = asicContent.getSignatureDocuments();
        if (Utils.isCollectionNotEmpty(existingSignatures)) {
            return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE.replace("001", getSignatureNumber(existingSignatures));
        } else {
            return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE;
        }
    }
	
    private String getSignatureNumber(List<DSSDocument> existingSignatures) {
        int signatureNumber = existingSignatures.size() + 1;
        String sigNumberStr = String.valueOf(signatureNumber);
        String zeroPad = "000";
        return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

    @Override
    public String getTimestampFilename() {
        throw new UnsupportedOperationException("Timestamp file cannot be added with ASiC-E + XAdES");
    }

    @Override
    public boolean isOpenDocument() {
        return false;
    }

}

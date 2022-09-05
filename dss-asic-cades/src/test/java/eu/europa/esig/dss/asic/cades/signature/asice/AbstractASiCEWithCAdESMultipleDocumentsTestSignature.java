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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCEWithCAdESMultipleDocumentsTestSignature extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.ASICE;
    }

    @Override
    protected boolean isBaselineT() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
                || SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
    }

    @Override
    protected boolean isBaselineLTA() {
        return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        assertNotNull(asicContent.getMimeTypeDocument());
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignedDocuments()));
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getRootLevelSignedDocuments()));

        assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()));
        for (DSSDocument signatureDocument : asicContent.getSignatureDocuments()) {
            assertNotNull(DSSUtils.toCMSSignedData(signatureDocument));
        }

        assertTrue(Utils.isCollectionNotEmpty(asicContent.getManifestDocuments()));

        assertFalse(Utils.isCollectionNotEmpty(asicContent.getUnsupportedDocuments()));
    }

}

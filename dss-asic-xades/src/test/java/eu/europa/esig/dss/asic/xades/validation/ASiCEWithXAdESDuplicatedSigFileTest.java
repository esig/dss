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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ASiCEWithXAdESDuplicatedSigFileTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/asic-xades-duplicated-sig-file.sce");
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<String> signatureIdList = diagnosticData.getSignatureIdList();
        for (String signatureId : signatureIdList) {
            SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
            if (diagnosticData.isBLevelTechnicallyValid(signatureId) && !signatureWrapper.isCounterSignature()) {
                List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
                assertEquals(3, Utils.collectionSize(retrievedOriginalDocuments));
                for (DSSDocument document : retrievedOriginalDocuments) {
                    assertNotNull(document);
                }
            }
        }
    }

}

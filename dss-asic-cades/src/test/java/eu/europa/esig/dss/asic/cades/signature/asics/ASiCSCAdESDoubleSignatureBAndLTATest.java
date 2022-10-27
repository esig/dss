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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSCAdESDoubleSignatureBAndLTATest extends AbstractASiCSCAdESTestSignature {

    private final DSSDocument ORIGINAL_DOC = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeType.TEXT);

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String firstSignatureId;

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = ORIGINAL_DOC;

        DSSDocument firstSignedDocument = super.sign();
        assertNotNull(firstSignedDocument);

        SignedDocumentValidator validator = getValidator(firstSignedDocument);
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        firstSignatureId = signatures.get(0).getDSSId().asXmlId();

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        documentToSign = firstSignedDocument;

        DSSDocument secondSignedDocument = super.sign();
        assertNotNull(secondSignedDocument);

        documentToSign = ORIGINAL_DOC;

        return secondSignedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean bLevelSigFound = false;
        boolean ltaLevelSigFound = false;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B.equals(signature.getSignatureFormat())) {
                assertEquals(firstSignatureId, signature.getId());
                bLevelSigFound = true;
            } else if (SignatureLevel.CAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
                ltaLevelSigFound = true;
            }
        }
        assertTrue(bLevelSigFound);
        assertTrue(ltaLevelSigFound);
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

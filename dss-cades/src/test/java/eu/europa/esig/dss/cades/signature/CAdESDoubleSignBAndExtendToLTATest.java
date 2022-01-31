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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CAdESDoubleSignBAndExtendToLTATest extends AbstractCAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text");
    }

    @Override
    protected DSSDocument sign() {
        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        documentToSign = signedDocument;
        DSSDocument doubleSignedDocument = super.sign();

        CAdESSignatureParameters extensionParameters = new CAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        DSSDocument extendedDocument = service.extendDocument(doubleSignedDocument, extensionParameters);

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        documentToSign = originalDocument;
        return extendedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.CAdES_BASELINE_LTA, signature.getSignatureFormat());
        }
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

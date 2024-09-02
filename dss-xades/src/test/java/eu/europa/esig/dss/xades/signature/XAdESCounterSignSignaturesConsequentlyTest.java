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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESCounterSignSignaturesConsequentlyTest extends AbstractXAdESCounterSignatureTest {

    private final DSSDocument ORIGINAL_DOCUMENT = new FileDocument(new File("src/test/resources/sample.xml"));

    private XAdESService service;
    private Date signingDate;

    private DSSDocument documentToSign;
    private String signingAlias;

    private XAdESSignatureParameters signatureParameters;
    private XAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    void init() throws Exception {
        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = ORIGINAL_DOCUMENT;
        signingDate = new Date();

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        counterSignatureParameters = new XAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        return signatureParameters;
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = GOOD_USER;

        DSSDocument signedDocument = super.sign();

        awaitOneSecond();

        documentToSign = signedDocument;
        signingAlias = EE_GOOD_USER;

        DSSDocument doubleSignedDocument = super.sign();

        documentToSign = ORIGINAL_DOCUMENT;

        return doubleSignedDocument;
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        SignedDocumentValidator validator = getValidator(signatureDocument);
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        signingAlias = RSA_SHA3_USER;
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatures.get(0).getId());

        signingAlias = SELF_SIGNED_USER;
        return super.counterSign(counterSigned, signatures.get(1).getId());
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(4, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);
        assertEquals(2, signatures.size());

        for (AdvancedSignature signature : signatures) {
            List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
            assertEquals(1, counterSignatures.size());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void checkCertificateChain(DiagnosticData diagnosticData) {
        // skip (different signers)
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip (different signers)
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}

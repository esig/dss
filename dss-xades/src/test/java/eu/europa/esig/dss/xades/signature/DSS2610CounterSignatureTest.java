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
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/*
 * In this unit test no revocation data shall be requested for counter-signature on validation
 */
class DSS2610CounterSignatureTest extends AbstractXAdESCounterSignatureTest {

    private String signingAlias;

    private XAdESService service;
    private DSSDocument documentToSign;

    private Date signingDate;

    private MockOnlineCRLSource mockOnlineCRLSource;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MONTH, -1);
        signingDate = calendar.getTime();

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsaByTime(signingDate));

        mockOnlineCRLSource = new MockOnlineCRLSource();
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = RSA_SHA3_USER;
        return super.sign();
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        signingAlias = GOOD_USER;
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatureId);

        XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        return service.extendDocument(counterSigned, extensionParameters);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        signingAlias = RSA_SHA3_USER;
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(mockOnlineCRLSource);
        validator.setCertificateVerifier(certificateVerifier);

        return validator;
    }

    @Override
    protected Reports verify(DSSDocument signedDocument) {
        Reports verify = super.verify(signedDocument);
        assertEquals(0, mockOnlineCRLSource.requestCounter);
        return verify;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean bLevelSigFound = false;
        boolean ltaLevelSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            if (SignatureLevel.XAdES_BASELINE_B.equals(diagnosticData.getSignatureFormat(sigId))) {
                bLevelSigFound = true;
            } else if (SignatureLevel.XAdES_BASELINE_LTA.equals(diagnosticData.getSignatureFormat(sigId))) {
                ltaLevelSigFound = true;
            }
        }
        assertTrue(bLevelSigFound);
        assertTrue(ltaLevelSigFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        List<String> signatureIdList = simpleReport.getSignatureIdList();
        for (String sigId : signatureIdList) {
            assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(sigId));
        }
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

    private class MockOnlineCRLSource extends OnlineCRLSource {

        private int requestCounter = 0;

        @Override
        public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            ++requestCounter;
            return super.getRevocationToken(certificateToken, issuerCertificateToken);
        }
    }

}

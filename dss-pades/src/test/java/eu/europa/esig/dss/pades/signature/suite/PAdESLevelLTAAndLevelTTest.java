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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESLevelLTAAndLevelTTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date signingTime;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        signingTime = new Date();
        signingAlias = GOOD_USER;

        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        signatureParameters.bLevel().setSigningDate(signingTime);

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();
        documentToSign = signedDocument;

        signingAlias = RSA_SHA3_USER;
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(signingTime);

        DSSDocument doubleSignedDocument = super.sign();

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        PAdESTimestampService timestampService = new PAdESTimestampService(getGoodTsa());

        DSSDocument timestampedDocument = timestampService.timestampDocument(doubleSignedDocument, timestampParameters);
        timestampedDocument.setName(doubleSignedDocument.getName());
        return timestampedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatures.get(0).getSignatureFormat());
        assertEquals(SignatureLevel.PAdES_BASELINE_T, signatures.get(1).getSignatureFormat());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        boolean signTstFound = false;
        boolean firstDocTstFound = false;
        boolean secondDocTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(0, timestampWrapper.getTimestampedTimestamps().size());
                signTstFound = true;
            } else if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                if (timestampWrapper.getTimestampedTimestamps().size() == 1) {
                    assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                    firstDocTstFound = true;
                } else if (timestampWrapper.getTimestampedTimestamps().size() == 2) {
                    assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
                    secondDocTstFound = true;
                }
            }
        }
        assertTrue(signTstFound);
        assertTrue(firstDocTstFound);
        assertTrue(secondDocTstFound);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.get(0).getSignatureScopes().size());
        assertEquals(SignatureScopeType.PARTIAL, signatures.get(0).getSignatureScopes().get(0).getScope());
        assertEquals(1, signatures.get(1).getSignatureScopes().size());
        assertEquals(SignatureScopeType.PARTIAL, signatures.get(1).getSignatureScopes().get(0).getScope());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected void validateETSIDSSType(SADSSType dss) {
        assertNotNull(dss);
    }

    @Override
    protected void validateETSIVRIType(SAVRIType vri) {
        assertNotNull(vri);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}

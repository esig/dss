/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.timestamp.suite;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESTimestampSignedPdfTest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setLocation("Luxembourg");
        signatureParameters.setReason("DSS testing");
        signatureParameters.setContactInfo("Jira");

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        service.setTspSource(getGoodTsa());
        documentToSign = service.timestamp(originalDocument, new PAdESTimestampParameters());

        DSSDocument signedDocument = super.sign();

        service.setTspSource(getAlternateGoodTsa());
        DSSDocument timestampedDocument = service.timestamp(signedDocument, new PAdESTimestampParameters());
        PDFDocumentAnalyzer pdfDocumentAnalyzer = new PDFDocumentAnalyzer(timestampedDocument);
        assertEquals(0, pdfDocumentAnalyzer.getDssDictionaries().size());

        service.setTspSource(getSelfSignedTsa());
        timestampedDocument = service.timestamp(timestampedDocument, new PAdESTimestampParameters());
        pdfDocumentAnalyzer = new PDFDocumentAnalyzer(timestampedDocument);
        assertEquals(1, pdfDocumentAnalyzer.getDssDictionaries().size());

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        return timestampedDocument;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        List<RelatedRevocationWrapper> dssRevocations = foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.DSS_DICTIONARY);
        List<String> dssRevocationIds = dssRevocations.stream().map(r -> r.getId()).collect(Collectors.toList());

        int notSelfSignedTsps = 0;
        int selfSignedTsps = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
            if (!signingCertificate.isSelfSigned()) {
                List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
                for (RevocationWrapper revocationWrapper : certificateRevocationData) {
                    assertTrue(dssRevocationIds.contains(revocationWrapper.getId()));
                }
                ++notSelfSignedTsps;
            } else {
                ++selfSignedTsps;
            }
        }
        assertEquals(2, notSelfSignedTsps);
        assertEquals(1, selfSignedTsps);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(1, signature.getSignatureScopes().size());
        assertEquals(SignatureScopeType.PARTIAL, signature.getSignatureScopes().get(0).getScope());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int docTstCounter = 0;
        int sigTstChanges = 0;
        int sigTstNoChanges = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedSignatures())) {
                if (timestampWrapper.arePdfObjectModificationsDetected()) {
                    ++sigTstChanges;
                } else {
                    ++sigTstNoChanges;
                }
            } else {
                assertTrue(timestampWrapper.arePdfObjectModificationsDetected());
                ++docTstCounter;
            }
        }
        assertEquals(1, docTstCounter);
        assertEquals(1, sigTstChanges);
        assertEquals(1, sigTstNoChanges);
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
        return GOOD_USER;
    }

}

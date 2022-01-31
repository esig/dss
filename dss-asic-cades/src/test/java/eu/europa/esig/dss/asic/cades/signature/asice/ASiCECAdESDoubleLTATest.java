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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCECAdESDoubleLTATest extends AbstractASiCECAdESTestSignature {

    private static DSSDocument originalDocument;

    private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeType.TEXT);
        signingAlias = EE_GOOD_USER;

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        service.setTspSource(getGoodTsa());
        ASiCWithCAdESSignatureParameters extensionParameters = new ASiCWithCAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);

        signingAlias = RSA_SHA3_USER;
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        service.setTspSource(getAlternateGoodTsa());
        documentToSign = extendedDocument;
        DSSDocument doubleSignedDocument = super.sign();

        service.setTspSource(getGoodTsa());
        extendedDocument = service.extendDocument(doubleSignedDocument, extensionParameters);

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA); // enforce LTA level for validation
        return extendedDocument;
    }

    @Override
    protected void checkManifests(List<DSSDocument> manifestDocuments) {
        super.checkManifests(manifestDocuments);

        int archiveTstCounter = 0;
        boolean secondArchiveTstFound = false;
        assertEquals(4, manifestDocuments.size());
        for (DSSDocument document : manifestDocuments) {
            boolean signedFileFound = false;
            boolean timestampedSignatureFound = false;
            ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(document);
            for (ManifestEntry entry : manifestFile.getEntries()) {
                if (originalDocument.getName().equals(entry.getFileName())) {
                    assertEquals(MimeType.TEXT, entry.getMimeType());
                    signedFileFound = true;
                }
                if (entry.getFileName().contains("signature")) {
                    assertEquals(MimeType.PKCS7, entry.getMimeType());
                    timestampedSignatureFound = true;
                }
                if (entry.getFileName().contains("timestamp")) {
                    assertEquals(MimeType.TST, entry.getMimeType());
                    secondArchiveTstFound = true;
                }
            }
            if (timestampedSignatureFound) {
                ++archiveTstCounter;
            }
            assertTrue(signedFileFound);
        }
        assertEquals(2, archiveTstCounter);
        assertTrue(secondArchiveTstFound);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        List<String> revocationDataIds = new ArrayList<>();
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<RelatedRevocationWrapper> revocationData = signatureWrapper.foundRevocations().getRelatedRevocationData();
            assertTrue(Utils.isCollectionNotEmpty(revocationData));
            assertDoesNotContainRevocation(revocationDataIds, revocationData);
        }
        boolean extendedTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                List<RelatedRevocationWrapper> revocationData = timestampWrapper.foundRevocations().getRelatedRevocationData();
                if (Utils.isCollectionNotEmpty(revocationData)) {
                    assertDoesNotContainRevocation(revocationDataIds, revocationData);
                    extendedTstFound = true;
                }
            }
        }
        assertTrue(extendedTstFound);
    }

    private void assertDoesNotContainRevocation(List<String> revocationDataIds, List<RelatedRevocationWrapper> revocationData) {
        List<String> currentRevocationDataIds = revocationData.stream().map(r -> r.getId()).collect(Collectors.toList());
        for (String revocationId : currentRevocationDataIds) {
            assertFalse(revocationDataIds.contains(revocationId));
            revocationDataIds.add(revocationId);
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
    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
        }
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
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
        return signingAlias;
    }

}

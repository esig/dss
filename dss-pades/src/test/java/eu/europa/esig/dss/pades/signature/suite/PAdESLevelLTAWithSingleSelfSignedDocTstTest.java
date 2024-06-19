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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESLevelLTAWithSingleSelfSignedDocTstTest extends AbstractPAdESTestSignature {

    private CertificateVerifier certificateVerifier;
    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        certificateVerifier = getOfflineCertificateVerifier();
        service = new PAdESService(certificateVerifier);
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        PDFSignatureService pdfSignatureService = new ServiceLoaderPdfObjFactory().newPAdESSignatureService();

        PDFDocumentAnalyzer pdfDocumentAnalyzer = new PDFDocumentAnalyzer(signedDocument);
        pdfDocumentAnalyzer.setCertificateVerifier(getCompleteCertificateVerifier());
        PdfValidationDataContainer validationData = pdfDocumentAnalyzer.getValidationData(pdfDocumentAnalyzer.getSignatures(), Collections.emptyList());

        signedDocument = pdfSignatureService.addDssDictionary(signedDocument, validationData);
        signedDocument = new PAdESTimestampService(getSelfSignedTsa()).timestampDocument(signedDocument, new PAdESTimestampParameters());

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        signedDocument.setName("signed.pdf");
        signedDocument.setMimeType(MimeTypeEnum.PDF);
        return signedDocument;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocument = new InMemoryDocument(byteArray);

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        service.setTspSource(getGoodTsa());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        Exception exception = assertThrows(AlertException.class, () ->
                service.extendDocument(signedDocument, signatureParameters));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to T-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        assertNotNull(extendedDocument);

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        exception = assertThrows(AlertException.class, () ->
                service.extendDocument(signedDocument, signatureParameters));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        assertNotNull(extendedDocument);

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        extendedDocument = service.extendDocument(signedDocument, signatureParameters);
        SignedDocumentValidator validator = getValidator(extendedDocument);
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signatures.get(0).getDataFoundUpToLevel());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
        assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedCertificates()));
        assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedTimestamps()));

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(1, signatureWrapper.getDocumentTimestamps().size());
        assertEquals(1, signatureWrapper.getTLevelTimestamps().size());
        assertEquals(1, signatureWrapper.getALevelTimestamps().size());
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
        return RSA_SHA3_USER;
    }

}
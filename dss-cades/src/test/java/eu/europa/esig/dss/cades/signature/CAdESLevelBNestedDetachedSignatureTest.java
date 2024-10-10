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
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelBNestedDetachedSignatureTest extends AbstractCAdESTestSignature {

    private static DSSDocument originalDocument;
    private static DSSDocument nestedSignature;
    private static Date date;

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeAll
    static void initBeforeAll() {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        date = new Date();
    }

    @BeforeEach
    void init() throws Exception {
        documentToSign = originalDocument;

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(date);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setParallelSignature(false);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        nestedSignature = super.sign();
        documentToSign = nestedSignature;
        DSSDocument signatureDocument = super.sign();
        return signatureDocument;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(nestedSignature);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, diagnosticData.getSignatures().size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        super.verifyOriginalDocuments(validator, diagnosticData);

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());

        DSSDocument nestedSignatureDocument = originalDocuments.get(0);

        CMSDocumentValidator cmsDocumentValidator = new CMSDocumentValidator(nestedSignatureDocument);
        cmsDocumentValidator.setCertificateVerifier(getOfflineCertificateVerifier());
        cmsDocumentValidator.setDetachedContents(Collections.singletonList(originalDocument));

        Reports reports = cmsDocumentValidator.validateDocument();
        diagnosticData = reports.getDiagnosticData();

        assertEquals(1, diagnosticData.getSignatures().size());
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

        originalDocuments = cmsDocumentValidator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());
        assertArrayEquals(DSSUtils.toByteArray(originalDocument), DSSUtils.toByteArray(originalDocuments.get(0)));
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
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

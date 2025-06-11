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
package eu.europa.esig.dss.cms.stream.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.AbstractCAdESTestSignature;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class CAdESDoubleLTALargeFileTest extends AbstractCAdESTestSignature {

    private FileDocument documentToSign;
    private CAdESSignatureParameters parameters;
    private CAdESService service;

    private TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder;

    @BeforeEach
    void init() throws IOException {
        documentToSign = generateLargeFile();

        parameters = new CAdESSignatureParameters();
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setSigningCertificate(getSigningCert());
        parameters.setCertificateChain(getCertificateChain());
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
        archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
        parameters.setArchiveTimestampParameters(archiveTimeStampParameters);

        tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        service = new CAdESService(getCompleteCertificateVerifier());
        service.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
        service.setTspSource(getGoodTsa());
    }

    @AfterEach
    void clean() {
        File file = documentToSign.getFile();
        assertTrue(file.exists());
        assertTrue(file.delete());
        assertFalse(file.exists());

        tempFileResourcesHandlerBuilder.clear();
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument signed = sign();

        DSSDocument doubleLtaDoc = service.extendDocument(signed, parameters);

        assertNotNull(doubleLtaDoc.getName());
        assertNotNull(doubleLtaDoc.getMimeType());

        checkMimeType(doubleLtaDoc);

        Reports reports = verify(doubleLtaDoc);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertEquals(3, diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
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
        return parameters;
    }

}

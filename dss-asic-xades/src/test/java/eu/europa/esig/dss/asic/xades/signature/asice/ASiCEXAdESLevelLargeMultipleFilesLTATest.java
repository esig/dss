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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class ASiCEXAdESLevelLargeMultipleFilesLTATest extends AbstractASiCEWithXAdESMultipleDocumentsTestSignature {

    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private List<FileDocument> documentToSigns;

    private TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder;

    @BeforeEach
    void init() throws Exception {
        tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        SecureContainerHandlerBuilder secureContainerHandlerBuilder = new SecureContainerHandlerBuilder()
                .setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandlerBuilder);

        documentToSigns = new ArrayList<>();
        documentToSigns.add(generateLargeFile("1.bin"));
        documentToSigns.add(generateLargeFile("2.bin"));
        documentToSigns.add(generateLargeFile("3.bin"));

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        // precompute
        documentToSigns.parallelStream().forEach(d -> d.getDigestValue(DSSXMLUtils.getReferenceDigestAlgorithmOrDefault(signatureParameters)));

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @AfterEach
    void clean() {
        for (FileDocument fileDocument : documentToSigns) {
            File file = fileDocument.getFile();
            assertTrue(file.exists());
            assertTrue(file.delete());
            assertFalse(file.exists());
        }

        tempFileResourcesHandlerBuilder.clear();
    }

    @Test
    @Override
    public void signAndVerify() {
        final DSSDocument signedDocument = sign();

        assertNotNull(signedDocument.getName());
        assertNotNull(signedDocument.getMimeType());

        checkMimeType(signedDocument);

        verify(signedDocument);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        String signatureId = diagnosticData.getFirstSignatureId();
        for (TimestampWrapper wrapper : diagnosticData.getTimestampList(signatureId)) {
            boolean found = false;
            for (SignatureWrapper signatureWrapper : wrapper.getTimestampedSignatures()) {
                if (signatureId.equals(signatureWrapper.getId())) {
                    found = true;
                }
            }
            assertTrue(found);
        }
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return new ArrayList<>(documentToSigns);
    }

    @Override
    protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }


    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
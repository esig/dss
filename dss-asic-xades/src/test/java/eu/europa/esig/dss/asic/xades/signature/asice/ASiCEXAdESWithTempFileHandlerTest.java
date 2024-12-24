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
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCEXAdESWithTempFileHandlerTest extends AbstractASiCEXAdESTestSignature {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCEXAdESWithTempFileHandlerTest.class);

    private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
    }

    @Override
    protected DSSDocument sign() {
        TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        SecureContainerHandlerBuilder secureContainerHandlerBuilder = new SecureContainerHandlerBuilder()
                .setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandlerBuilder);

        Runtime.getRuntime().gc();
        double memoryBefore = getRuntimeMemoryInMegabytes();

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for getDataToSign() : {}Mb", memoryAfterGetDataToSign - memoryBefore);

        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        double memoryAfterSignDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for signDocument() : {}Mb", memoryAfterSignDocument - memoryBefore);
        assertInstanceOf(FileDocument.class, signedDocument);

        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument tLevelSignature = service.extendDocument(signedDocument, signatureParameters);

        double memoryTLevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for T-Level extendDocument() : {}Mb", memoryTLevelExtendDocument - memoryBefore);
        assertInstanceOf(FileDocument.class, tLevelSignature);

        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument ltLevelSignature = service.extendDocument(tLevelSignature, signatureParameters);

        double memoryLTLevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for LT-Level extendDocument() : {}Mb", memoryLTLevelExtendDocument - memoryBefore);
        assertInstanceOf(FileDocument.class, ltLevelSignature);

        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument ltaLevelSignature = service.extendDocument(ltLevelSignature, signatureParameters);

        double memoryLTALevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for LTA-Level extendDocument() : {}Mb", memoryLTALevelExtendDocument - memoryBefore);
        assertInstanceOf(FileDocument.class, ltaLevelSignature);

        FileDocument ltaSignatureFileDocument = (FileDocument) ltaLevelSignature;
        File ltaSignatureFile = ltaSignatureFileDocument.getFile();

        assertTrue(ltaSignatureFile.exists());

        File tempFile = null;
        try {
            tempFile = Files.createTempFile("dss", ".sce").toFile();
            try (InputStream is = Files.newInputStream(ltaSignatureFile.toPath());
                 OutputStream os = Files.newOutputStream(tempFile.toPath())) {
                Utils.copy(is, os);
            }

        } catch (IOException e) {
            fail(e);
        }

        assertTrue(ltaSignatureFile.exists());

        assertNotNull(tempFile);
        assertTrue(tempFile.exists());

        tempFileResourcesHandlerBuilder.clear();

        assertFalse(ltaSignatureFile.exists());
        assertTrue(tempFile.exists());

        return new FileDocument(tempFile);
    }

    private static double getRuntimeMemoryInMegabytes() {
        // Get the Java runtime
        Runtime runtime = Runtime.getRuntime();
        // Calculate the used memory
        double memory = runtime.totalMemory() - runtime.freeMemory();
        return bytesToMegabytes(memory);
    }

    private static double bytesToMegabytes(double bytes) {
        return bytes / (1024L * 1024L);
    }

    @Override
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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

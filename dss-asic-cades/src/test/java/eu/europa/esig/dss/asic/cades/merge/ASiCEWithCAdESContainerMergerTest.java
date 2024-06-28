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
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.timestamp.ASiCWithCAdESTimestampService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESContainerMergerTest extends AbstractPkiFactoryTestValidation {

    @Test
    void isSupportedTest() {
        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger();
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/tstNoMimeType.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip"))); // ASiC-E
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/open-document.odp")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    void createAndMergeTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(containerOne, containerTwo);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithCAdESContainerExtractor(containerTwo).extract();

        merger = new ASiCEWithCAdESContainerMerger(asicContentOne, asicContentTwo);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
    }

    @Test
    void mergeAsicWithZipTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeTypeEnum.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(asicContentOne, asicContentToAdd);
        DSSDocument mergedContainer = merger.merge();

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        merger = new ASiCEWithCAdESContainerMerger(containerOne, zipArchive);
        mergedContainer = merger.merge();

        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getContainerInfo().getContentFiles().size());
    }

    @Test
    void mergeTwoNotSignedZipTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/signable/document.odt");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        assertEquals("test-merged.zip", mergedContainer.getName());

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        mergedAsicContent = merger.mergeToASiCContent();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        merger = new ASiCEWithCAdESContainerMerger(firstAsicContent, secondAsicContent);
        mergedContainer = merger.merge();
        assertEquals("test-merged.zip", mergedContainer.getName());

        mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        mergedAsicContent = merger.mergeToASiCContent();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeTwoTimestampedContainersTest() {
        DSSDocument timestampedContainerOne = new FileDocument("src/test/resources/validation/tstNoMimeType.asice");
        DSSDocument timestampedContainerTwo = new FileDocument("src/test/resources/validation/tstWithEmptyCertSource.asice");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(timestampedContainerOne, timestampedContainerTwo);
        DSSDocument mergedContainer = merger.merge();

        assertEquals("tstNoMimeType-merged.asice", mergedContainer.getName());

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getTimestampList().size());

        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Test
    void mergeTimestampedAsicWithZipTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(getGoodTsa());

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        DSSDocument timestampedContainer = timestampService.timestamp(Arrays.asList(toSignDocument), timestampParameters);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeTypeEnum.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(timestampedContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(asicContentOne, asicContentToAdd);
        DSSDocument mergedContainer = merger.merge();

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getTimestampList().size());

        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        merger = new ASiCEWithCAdESContainerMerger(timestampedContainer, zipArchive);
        mergedContainer = merger.merge();

        validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        reports = validator.validateDocument();
        diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getTimestampList().size());
        assertEquals(2, diagnosticData.getContainerInfo().getContentFiles().size());
    }

    @Test
    void mergeSignedAndTimestampedContainersTest() {
        DSSDocument signedContainer = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        DSSDocument timestampedContainer = new FileDocument("src/test/resources/validation/tstNoMimeType.asice");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(signedContainer, timestampedContainer);
        DSSDocument mergedContainer = merger.merge();

        assertEquals("multifiles-ok-merged.asice", mergedContainer.getName());

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getTimestampList().size()); // timestamp file + content timestamp

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signatureWrapper.isSignatureIntact());
        assertTrue(signatureWrapper.isSignatureValid());

        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Test
    void mergeLTALevelContainersTest() {
        DSSDocument signedContainer = new FileDocument("src/test/resources/validation/asice-level-lta-with-custom-manifest-namespace.sce");
        DSSDocument timestampedContainer = new FileDocument("src/test/resources/validation/cades-lta-alternative-naming.sce");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(signedContainer, timestampedContainer);
        DSSDocument mergedContainer = merger.merge();

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(4, diagnosticData.getTimestampList().size()); // 2 * signature tst + archive tst

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signatureWrapper.isSignatureIntact());
        assertTrue(signatureWrapper.isSignatureValid());

        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Test
    void mergeSignaturesWithoutManifestTest() {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeTypeEnum.PKCS7)));
        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeTypeEnum.TEXT)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeTypeEnum.PKCS7)));
        secondASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "bye.txt", MimeTypeEnum.TEXT)));

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-E with CAdES containers. " +
                "A signature with filename 'META-INF/signature.p7s' does not have a corresponding manifest file!", exception.getMessage());
    }

    @Test
    void mergeMultipleContainersTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerThree = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(containerOne, containerTwo, containerThree);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());

        List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
        assertEquals(1, manifestFiles.size());

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithCAdESContainerExtractor(containerTwo).extract();
        ASiCContent asicContentThree = new ASiCWithCAdESContainerExtractor(containerTwo).extract();

        merger = new ASiCEWithCAdESContainerMerger(asicContentOne, asicContentTwo, asicContentThree);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());
        assertEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
        assertEquals(diagnosticData.getSignatures().get(1).getSignatureFilename(), diagnosticData.getSignatures().get(2).getSignatureFilename());

        manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
        assertEquals(1, manifestFiles.size());
    }

    @Test
    void mergeMultipleContainersWithDifferentSignatureNamesTest() throws IOException {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signatureAAA.p7s");
        service.setAsicFilenameFactory(filenameFactory);

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        filenameFactory.setSignatureFilename("signatureBBB.p7s");

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        filenameFactory.setSignatureFilename("signatureCCC.p7s");

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerThree = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(containerOne, containerTwo, containerThree);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());

        List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
        assertEquals(3, manifestFiles.size());
        assertNotEquals(manifestFiles.get(0).getFilename(), manifestFiles.get(1).getFilename());
        assertNotEquals(manifestFiles.get(1).getFilename(), manifestFiles.get(2).getFilename());
        assertNotEquals(manifestFiles.get(0).getFilename(), manifestFiles.get(2).getFilename());

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithCAdESContainerExtractor(containerTwo).extract();
        ASiCContent asicContentThree = new ASiCWithCAdESContainerExtractor(containerThree).extract();

        merger = new ASiCEWithCAdESContainerMerger(asicContentOne, asicContentTwo, asicContentThree);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());
        assertNotEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
        assertNotEquals(diagnosticData.getSignatures().get(1).getSignatureFilename(), diagnosticData.getSignatures().get(2).getSignatureFilename());
        assertNotEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(2).getSignatureFilename());

        boolean aaaNameFound = false;
        boolean bbbNameFound = false;
        boolean cccNameFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if ("META-INF/signatureAAA.p7s".equals(signatureWrapper.getSignatureFilename())) {
                aaaNameFound = true;
            } else if ("META-INF/signatureBBB.p7s".equals(signatureWrapper.getSignatureFilename())) {
                bbbNameFound = true;
            } else if ("META-INF/signatureCCC.p7s".equals(signatureWrapper.getSignatureFilename())) {
                cccNameFound = true;
            }
        }
        assertTrue(aaaNameFound);
        assertTrue(bbbNameFound);
        assertTrue(cccNameFound);

        manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
        assertEquals(3, manifestFiles.size());
        assertNotEquals(manifestFiles.get(0).getFilename(), manifestFiles.get(1).getFilename());
        assertNotEquals(manifestFiles.get(1).getFilename(), manifestFiles.get(2).getFilename());
        assertNotEquals(manifestFiles.get(0).getFilename(), manifestFiles.get(2).getFilename());

        boolean firstManifestNameFound = false;
        boolean secondManifestNameFound = false;
        boolean thirdManifestNameFound = false;
        for (XmlManifestFile manifestFile : manifestFiles) {
            if ("META-INF/ASiCManifest001.xml".equals(manifestFile.getFilename())) {
                firstManifestNameFound = true;
            } else if ("META-INF/ASiCManifest002.xml".equals(manifestFile.getFilename())) {
                secondManifestNameFound = true;
            } else if ("META-INF/ASiCManifest003.xml".equals(manifestFile.getFilename())) {
                thirdManifestNameFound = true;
            }
        }
        assertTrue(firstManifestNameFound);
        assertTrue(secondManifestNameFound);
        assertTrue(thirdManifestNameFound);
    }

    @Test
    void mergeWithEvidenceRecordContainerTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeTstContainerWithEvidenceRecordContainerTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/tstNoMimeType.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeEvidenceRecordContainerWithNoSignatureContainerTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeDifferentEvidenceRecordTypeContainersTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-one-file.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeEvidenceRecordContainersDiffSignerFileNamesTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-multi-files.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge containers. " +
                "Containers contain different documents under the same name : test.txt!", exception.getMessage());
    }

    @Test
    void mergeSameEvidenceRecordTypeContainersTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-chain-renewal.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-multi-files.asice");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        assertTrue(allDocumentNames.contains("test.txt"));
        assertTrue(allDocumentNames.contains("test2.txt"));
        assertTrue(allDocumentNames.contains("META-INF/evidencerecord.ers"));
        assertTrue(allDocumentNames.contains("META-INF/evidencerecord002.ers"));
        assertTrue(allDocumentNames.contains("META-INF/ASiCEvidenceRecordManifest.xml"));
        assertTrue(allDocumentNames.contains("META-INF/ASiCEvidenceRecordManifest002.xml"));

        boolean firstERFound = false;
        boolean secondERFound = false;
        for (DSSDocument erManifest : mergedAsicContent.getEvidenceRecordManifestDocuments()) {
            ManifestFile manifestFile = ASiCManifestParser.getManifestFile(erManifest);
            assertNotNull(manifestFile);

            if ("META-INF/evidencerecord.ers".equals(manifestFile.getSignatureFilename())) {
                firstERFound = true;
            } else if ("META-INF/evidencerecord002.ers".equals(manifestFile.getSignatureFilename())) {
                secondERFound = true;
            }
        }
        assertTrue(firstERFound);
        assertTrue(secondERFound);
    }

    @Test
    void mergeZeroFilesTest() {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger(new DSSDocument[]{}));
        assertEquals("At least one document shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger(new ASiCContent[]{}));
        assertEquals("At least one ASiCContent shall be provided!", exception.getMessage());

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger();
        exception = assertThrows(NullPointerException.class, () -> merger.merge());
        assertEquals("At least one container shall be provided!", exception.getMessage());
    }

    @Test
    void mergeNullFileTest() {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger(new DSSDocument[]{ null }));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger(new ASiCContent[]{ null }));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger((DSSDocument) null));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithCAdESContainerMerger((ASiCContent) null));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());
    }

    @Test
    void mergeOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(document);
        DSSDocument mergedDocument = merger.merge();

        ASiCContent asicContent = new ASiCWithCAdESContainerExtractor(document).extract();
        ASiCContent mergedAsicContent = new ASiCWithCAdESContainerExtractor(mergedDocument).extract();
        // return same document

        assertEquals(asicContent.getContainerType(), mergedAsicContent.getContainerType());
        assertEquals(asicContent.getZipComment(), mergedAsicContent.getZipComment());
        assertDocumentsEqual(asicContent.getSignedDocuments(), mergedAsicContent.getSignedDocuments());
        assertDocumentsEqual(asicContent.getContainerDocuments(), mergedAsicContent.getContainerDocuments());
        assertDocumentsEqual(asicContent.getSignatureDocuments(), mergedAsicContent.getSignatureDocuments());
        assertDocumentsEqual(asicContent.getTimestampDocuments(), mergedAsicContent.getTimestampDocuments());
        assertDocumentsEqual(asicContent.getManifestDocuments(), mergedAsicContent.getManifestDocuments());
        assertDocumentsEqual(asicContent.getArchiveManifestDocuments(), mergedAsicContent.getArchiveManifestDocuments());
        assertDocumentsEqual(asicContent.getUnsupportedDocuments(), mergedAsicContent.getUnsupportedDocuments());
        assertDocumentsEqual(asicContent.getFolders(), mergedAsicContent.getFolders());

        merger = new ASiCEWithCAdESContainerMerger(asicContent);
        mergedAsicContent = merger.mergeToASiCContent();

        assertEquals(asicContent.getContainerType(), mergedAsicContent.getContainerType());
        assertEquals(asicContent.getZipComment(), mergedAsicContent.getZipComment());
        assertDocumentsEqual(asicContent.getSignedDocuments(), mergedAsicContent.getSignedDocuments());
        assertDocumentsEqual(asicContent.getContainerDocuments(), mergedAsicContent.getContainerDocuments());
        assertDocumentsEqual(asicContent.getSignatureDocuments(), mergedAsicContent.getSignatureDocuments());
        assertDocumentsEqual(asicContent.getTimestampDocuments(), mergedAsicContent.getTimestampDocuments());
        assertDocumentsEqual(asicContent.getManifestDocuments(), mergedAsicContent.getManifestDocuments());
        assertDocumentsEqual(asicContent.getArchiveManifestDocuments(), mergedAsicContent.getArchiveManifestDocuments());
        assertDocumentsEqual(asicContent.getUnsupportedDocuments(), mergedAsicContent.getUnsupportedDocuments());
        assertDocumentsEqual(asicContent.getFolders(), mergedAsicContent.getFolders());
    }

    private void assertDocumentsEqual(List<DSSDocument> documentListOne, List<DSSDocument> documentListTwo) {
        assertEquals(new HashSet<>(DSSUtils.getDocumentNames(documentListOne)), new HashSet<>(DSSUtils.getDocumentNames(documentListTwo)));

        for (String documentName : DSSUtils.getDocumentNames(documentListOne)) {
            DSSDocument documentOne = DSSUtils.getDocumentWithName(documentListOne, documentName);
            assertNotNull(documentOne);
            DSSDocument documentTwo = DSSUtils.getDocumentWithName(documentListTwo, documentName);
            assertNotNull(documentTwo);
            assertTrue(Arrays.equals(DSSUtils.toByteArray(documentOne), DSSUtils.toByteArray(documentTwo)));
        }
    }

    @Test
    void mergeWithDifferentZipCommentTest() {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setZipComment(ASiCUtils.getZipComment(MimeTypeEnum.ASICE));
        secondASiCContent.setZipComment(ASiCUtils.getZipComment(MimeTypeEnum.ZIP));

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertTrue(exception.getMessage().contains("Unable to merge containers. Containers contain different zip comments"));
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertEquals(getExpectedASiCContainerType(), diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    private ASiCContainerType getExpectedASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

        if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
            for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
                SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

                SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
                assertNotNull(signatureIdentifier);

                assertNotNull(signatureIdentifier.getSignatureValue());
                assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
            }
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

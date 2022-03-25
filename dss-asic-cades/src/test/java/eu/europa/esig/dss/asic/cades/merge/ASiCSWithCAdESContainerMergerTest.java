package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.timestamp.ASiCWithCAdESTimestampService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSWithCAdESContainerMergerTest extends
        AbstractPkiFactoryTestValidation<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    @Test
    public void isSupportedTest() {
        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger();
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/open-document.odp")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip"))); // ASiC-E
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/asic_CAdES.zip")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    public void createAndMergeTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(containerOne, containerTwo);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithCAdESContainerExtractor(containerTwo).extract();

        merger = new ASiCSWithCAdESContainerMerger(asicContentOne, asicContentTwo);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
    }

    @Test
    public void mergeAsicWithZipTest() throws Exception {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(asicContentOne, asicContentToAdd);
        DSSDocument mergedContainer = merger.merge();

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        merger = new ASiCSWithCAdESContainerMerger(containerOne, zipArchive);
        mergedContainer = merger.merge();

        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());

        containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));
    }

    @Test
    public void mergeTwoNotSignedZipTest() throws Exception {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/signable/document.odt");

        ASiCContent firstAsicContent = new ASiCWithCAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithCAdESContainerExtractor(secondContainer).extract();

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstContainer, secondContainer);
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

        merger = new ASiCSWithCAdESContainerMerger(firstAsicContent, secondAsicContent);
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
    public void mergeTimestampedAsicWithZipTest() throws Exception {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(getGoodTsa());

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        DSSDocument timestampedContainer = timestampService.timestamp(Arrays.asList(toSignDocument), timestampParameters);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(timestampedContainer).extract();

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(asicContentOne, asicContentToAdd);
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

        merger = new ASiCSWithCAdESContainerMerger(timestampedContainer, zipArchive);
        mergedContainer = merger.merge();

        validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        reports = validator.validateDocument();

        diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getTimestampList().size());

        containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));
    }

    @Test
    public void mergeTimestampedMultipleDocsAsicWithZipTest() throws Exception {
        List<DSSDocument> toSignDocuments = Arrays.asList(
                new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT),
                new FileDocument("src/test/resources/signable/test.txt"));
        ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(getGoodTsa());

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        DSSDocument timestampedContainer = timestampService.timestamp(toSignDocuments, timestampParameters);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(timestampedContainer).extract();

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(asicContentOne, asicContentToAdd);
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

        assertEquals(3, timestampWrapper.getTimestampScopes().size()); // 2 signer docs + package.zip

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        merger = new ASiCSWithCAdESContainerMerger(timestampedContainer, zipArchive);
        mergedContainer = merger.merge();

        validator = SignedDocumentValidator.fromDocument(mergedContainer);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        reports = validator.validateDocument();

        diagnosticData = reports.getDiagnosticData();
        assertEquals(0, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getTimestampList().size());

        timestampWrapper = diagnosticData.getTimestampList().get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertEquals(3, timestampWrapper.getTimestampScopes().size()); // 2 signer docs + package.zip

        containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));
    }

    @Test
    public void mergeInvalidSigNameTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature001.xml", MimeType.XML)));

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-S with CAdES containers. " +
                "The signature document in one of the containers has invalid naming!", exception.getMessage());
    }

    @Test
    public void mergeContainerWithSignatureAndTimestampTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        firstASiCContent.setTimestampDocuments(Collections.singletonList(
                new InMemoryDocument("timestamp".getBytes(), "META-INF/timestamp.tst", MimeType.TST)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-S with CAdES containers. " +
                "One of the containers has more than one signature or timestamp documents!", exception.getMessage());
    }

    @Test
    public void mergeSignatureWithTimestampsTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        secondASiCContent.setTimestampDocuments(Collections.singletonList(
                new InMemoryDocument("timestamp".getBytes(), "META-INF/timestamp.tst", MimeType.TST)));

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-S with CAdES containers. " +
                "A container containing a timestamp file cannot be merged with other signed or timestamped container!", exception.getMessage());
    }

    @Test
    public void mergeWithMultipleSignerDocsTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        secondASiCContent.setSignedDocuments(Arrays.asList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT),
                new InMemoryDocument("Bye World!".getBytes(), "bye.txt", MimeType.TEXT)));

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-S with CAdES containers. " +
                "One of the containers has more than one signer documents!", exception.getMessage());
    }

    @Test
    public void mergeWithSignedDataDifferentNamesTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature.p7s", MimeType.PKCS7)));
        secondASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "bye.txt", MimeType.TEXT)));

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge ASiC-S with CAdES containers. " +
                "Signer documents have different names!", exception.getMessage());
    }

    @Test
    public void mergeMultipleContainersTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithCAdESService service = new ASiCWithCAdESService(getOfflineCertificateVerifier());

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
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

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(containerOne, containerTwo, containerThree);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());

        ASiCContent asicContentOne = new ASiCWithCAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithCAdESContainerExtractor(containerTwo).extract();
        ASiCContent asicContentThree = new ASiCWithCAdESContainerExtractor(containerThree).extract();

        merger = new ASiCSWithCAdESContainerMerger(asicContentOne, asicContentTwo, asicContentThree);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());
        assertEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
        assertEquals(diagnosticData.getSignatures().get(1).getSignatureFilename(), diagnosticData.getSignatures().get(2).getSignatureFilename());
    }

    @Test
    public void mergeZeroFilesTest() throws Exception {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger(new DSSDocument[]{}));
        assertEquals("At least one document shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger(new ASiCContent[]{}));
        assertEquals("At least one ASiCContent shall be provided!", exception.getMessage());

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger();
        exception = assertThrows(NullPointerException.class, () -> merger.merge());
        assertEquals("At least one container shall be provided!", exception.getMessage());
    }

    @Test
    public void mergeNullFileTest() throws Exception {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger(new DSSDocument[]{ null }));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger(new ASiCContent[]{ null }));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger((DSSDocument) null));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCSWithCAdESContainerMerger((ASiCContent) null));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());
    }

    @Test
    public void mergeOneFileTest() throws Exception {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");

        ASiCSWithCAdESContainerMerger merger = new ASiCSWithCAdESContainerMerger(document);
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

        merger = new ASiCSWithCAdESContainerMerger(asicContent);
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

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertEquals(getExpectedASiCContainerType(), diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    private ASiCContainerType getExpectedASiCContainerType() {
        return ASiCContainerType.ASiC_S;
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
    protected void checkMimeType(DiagnosticData diagnosticData) {
        super.checkMimeType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
                assertNotNull(signatureWrapper.getMimeType());
            } else {
                assertNull(signatureWrapper.getMimeType());
            }
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }
    
}

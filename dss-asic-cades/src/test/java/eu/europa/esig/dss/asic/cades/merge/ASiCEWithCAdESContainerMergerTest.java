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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESContainerMergerTest extends
        AbstractPkiFactoryTestValidation<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    @Test
    public void isSupportedTest() {
        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger();
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip"))); // ASiC-E
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/asic_CAdES.zip")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/open-document.odp")));
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
    public void mergeAsicWithZipTest() throws Exception {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
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

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
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
    public void mergeTwoNotSignedZipTest() throws Exception {
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
    public void mergeTwoTimestampedContainersTest() throws Exception {
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
    public void mergeTimestampedAsicWithZipTest() throws Exception {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(getGoodTsa());

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        DSSDocument timestampedContainer = timestampService.timestamp(Arrays.asList(toSignDocument), timestampParameters);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
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
    public void mergeSignedAndTimestampedContainersTest() throws Exception {
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
    public void mergeLTALevelContainersTest() throws Exception {
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
    public void mergeSignaturesWithoutManifestTest() throws Exception {
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

        ASiCEWithCAdESContainerMerger merger = new ASiCEWithCAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-E with CAdES containers. " +
                "A signature with filename 'META-INF/signature.p7s' does not have a corresponding manifest file!", exception.getMessage());
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

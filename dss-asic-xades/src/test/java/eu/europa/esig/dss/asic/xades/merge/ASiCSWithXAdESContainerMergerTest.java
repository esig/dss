package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSWithXAdESContainerMergerTest extends
        AbstractPkiFactoryTestValidation<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

    @Test
    public void isSupportedTest() {
        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger();
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/asic_xades.zip"))); // ASiC-E
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/open-document.odt")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    public void createAndMergeTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithXAdESService service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(containerOne, containerTwo);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());

        ASiCContent asicContentOne = new ASiCWithXAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithXAdESContainerExtractor(containerTwo).extract();

        merger = new ASiCSWithXAdESContainerMerger(asicContentOne, asicContentTwo);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(diagnosticData.getSignatures().get(0).getSignatureFilename(), diagnosticData.getSignatures().get(1).getSignatureFilename());
    }

    @Test
    public void mergeAsicWithZipTest() throws Exception {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        ASiCWithXAdESService service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeType.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithXAdESContainerExtractor(containerOne).extract();

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(asicContentOne, asicContentToAdd);
        DSSDocument mergedContainer = merger.merge();

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        ASiCSWithXAdESContainerMerger containerMerger = new ASiCSWithXAdESContainerMerger(containerOne, zipArchive);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> containerMerger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. Signer documents have different names!", exception.getMessage());
    }

    @Test
    public void mergeTwoNotSignedZipTest() throws Exception {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/signable/document.odt");

        ASiCContent firstAsicContent = new ASiCWithXAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithXAdESContainerExtractor(secondContainer).extract();

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
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

        merger = new ASiCSWithXAdESContainerMerger(firstAsicContent, secondAsicContent);
        mergedContainer = merger.merge();

        mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
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
    public void mergeDifferentNamespacesTest() {
        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/onefile-ok-another-asic-namespace.asics"));
        Exception exception = assertThrows(IllegalInputException.class, () -> merger.merge());
        assertEquals("Signature containers have different namespace prefixes!", exception.getMessage());
    }

    @Test
    public void mergeMultipleSignaturesTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        secondASiCContent.setSignatureDocuments(Arrays.asList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML),
                new InMemoryDocument("signature".getBytes(), "META-INF/signature001.xml", MimeType.XML)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. " +
                "One of the containers has more than one signature documents!", exception.getMessage());
    }

    @Test
    public void mergeInvalidSigNameTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signature001.xml", MimeType.XML)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. " +
                "The signature document in one of the containers has invalid naming!", exception.getMessage());
    }

    @Test
    public void mergeWithTimestampsTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        secondASiCContent.setTimestampDocuments(Collections.singletonList(
                new InMemoryDocument("timestamp".getBytes(), "META-INF/timestamp.tst", MimeType.TST)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. " +
                "One of the containers contains a detached timestamp!", exception.getMessage());
    }

    @Test
    public void mergeWithMultipleSignerDocsTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        secondASiCContent.setSignedDocuments(Arrays.asList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT),
                new InMemoryDocument("Bye World!".getBytes(), "bye.txt", MimeType.TEXT)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. " +
                "One of the containers has more than one signer documents!", exception.getMessage());
    }

    @Test
    public void mergeWithSignedDataDifferentNamesTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT)));
        secondASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeType.XML)));
        secondASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "bye.txt", MimeType.TEXT)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two ASiC-S with XAdES containers. " +
                "Signer documents have different names!", exception.getMessage());
    }

    @Test
    public void mergeWithSignedDataDifferentContentTest() throws Exception {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT)));
        secondASiCContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Bye World!".getBytes(), "hello.txt", MimeType.TEXT)));

        ASiCSWithXAdESContainerMerger merger = new ASiCSWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> merger.merge());
        assertEquals("Unable to merge two containers. " +
                "Containers contain different documents under the same name : hello.txt!", exception.getMessage());
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

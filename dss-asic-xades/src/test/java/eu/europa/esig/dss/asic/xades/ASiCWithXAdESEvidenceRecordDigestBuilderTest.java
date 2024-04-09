package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithXAdESEvidenceRecordDigestBuilderTest {

    @Test
    public void asicsWithXMLERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);

        Exception exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("DataObjectDigestBuilderFactory shall be set to continue! Please choose the corresponding " +
                "implementation for your evidence record type (e.g. XMLERS or ASN.1).", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("ASiCContentDocumentFilter shall be set to continue! " +
                "Use ASiCContentDocumentFilterFactory to facilitate configuration.", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.emptyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(0, digests.size());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());

        asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA512), digests.get(0).getValue());
    }

    @Test
    public void asicsWithERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        Exception exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("ASiCContentDocumentFilter shall be set to continue! " +
                "Use ASiCContentDocumentFilterFactory to facilitate configuration.", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());

        asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA512), digests.get(0).getValue());
    }

    @Test
    public void asiceWithXMLERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    public void asiceWithERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    public void asicsWithXMLERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    public void asicsWithERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    public void asiceWithXMLERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(2, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(2, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

    @Test
    public void asiceWithERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(2, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(2, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

    @Test
    public void asiceWithXMLERSOpenDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(12, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(12, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            if (DomUtils.isDOM(signedDocument)) {
                byte[] canonicalized = XMLCanonicalizer.createInstance().canonicalize(DomUtils.buildDOM(signedDocument));
                assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, canonicalized))));
            } else {
                assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
            }
        }
    }

    @Test
    public void asiceWithERSOpenDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(12, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(12, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

}

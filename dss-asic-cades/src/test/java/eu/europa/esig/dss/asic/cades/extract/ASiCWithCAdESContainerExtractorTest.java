package eu.europa.esig.dss.asic.cades.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCWithCAdESContainerExtractorTest {

    @Test
    public void asicsWithOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    public void asiceWithOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    public void asicsWithMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(2, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(2, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    public void asiceWithMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(2, asicContent.getSignedDocuments().size());
        assertEquals(2, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(2, asicContent.getSignedDocuments().size());
        assertEquals(2, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    public void openDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(12, asicContent.getSignedDocuments().size());
        assertEquals(5, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(0, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(2, asicContent.getUnsupportedDocuments().size()); // sig + manifest

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> DefaultASiCContainerExtractor.fromDocument(document));
        assertEquals("Document format not recognized/handled", exception.getMessage());
    }

    @Test
    public void asiceLtaTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/ASiC-E-CAdES-BpLTA.sce");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(1, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(1, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(1, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(1, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    public void asicWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce");

        ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(3, asicContent.getSignedDocuments().size());
        assertEquals(3, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(3, asicContent.getSignedDocuments().size());
        assertEquals(3, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

}

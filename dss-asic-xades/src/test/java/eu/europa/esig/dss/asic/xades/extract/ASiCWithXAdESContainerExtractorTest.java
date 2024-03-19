package eu.europa.esig.dss.asic.xades.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ASiCWithXAdESContainerExtractorTest {

    @Test
    public void asicsWithOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
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

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
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

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
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

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(2, asicContent.getSignedDocuments().size());
        assertEquals(2, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(2, asicContent.getSignatureDocuments().size());
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
        assertEquals(2, asicContent.getSignatureDocuments().size());
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

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(12, asicContent.getSignedDocuments().size());
        assertEquals(5, asicContent.getRootLevelSignedDocuments().size());
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
        assertEquals(12, asicContent.getSignedDocuments().size());
        assertEquals(5, asicContent.getRootLevelSignedDocuments().size());
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
    public void asicWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
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

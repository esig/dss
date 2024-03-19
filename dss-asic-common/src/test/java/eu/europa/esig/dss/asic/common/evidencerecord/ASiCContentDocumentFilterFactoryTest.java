package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ASiCContentDocumentFilterFactoryTest {

    @Test
    public void test() {
        ASiCContent asicContent = new ASiCContent();

        DSSDocument signedDoc = new InMemoryDocument("Hello".getBytes(), "signed.xml");
        asicContent.setSignedDocuments(Collections.singletonList(signedDoc));
        DSSDocument signatureDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/signature.xml");
        asicContent.setSignatureDocuments(Collections.singletonList(signatureDoc));
        DSSDocument timestampDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/timestamp.xml");
        asicContent.setTimestampDocuments(Collections.singletonList(timestampDoc));
        DSSDocument erDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/er.xml");
        asicContent.setEvidenceRecordDocuments(Collections.singletonList(erDoc));
        DSSDocument manifestDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/manifest.xml");
        asicContent.setManifestDocuments(Collections.singletonList(manifestDoc));
        DSSDocument archiveManifestDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/archiveManifest.xml");
        asicContent.setArchiveManifestDocuments(Collections.singletonList(archiveManifestDoc));
        DSSDocument erManifestDoc = new InMemoryDocument("Hello".getBytes(), "META-INF/erManifest.xml");
        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(erManifestDoc));
        DSSDocument unsupportedDoc = new InMemoryDocument("Hello".getBytes(), "path/unsupported.xml");
        asicContent.setUnsupportedDocuments(Collections.singletonList(unsupportedDoc));
        DSSDocument mimetype = new InMemoryDocument("mimetype".getBytes(), "mimetype");
        asicContent.setMimeTypeDocument(mimetype);

        ASiCContentDocumentFilter asicContentDocumentFilter = ASiCContentDocumentFilterFactory.emptyFilter();
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter();
        assertEquals(Collections.singletonList(signedDoc), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter("wrong.name");
        assertEquals(Collections.singletonList(signedDoc), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter(signedDoc.getName());
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.archiveDocumentsFilter();
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, manifestDoc, archiveManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.archiveDocumentsFilter("wrong.name");
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, manifestDoc, archiveManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.archiveDocumentsFilter(timestampDoc.getName(), archiveManifestDoc.getName());
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, manifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter.setManifestDocuments(false);
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allSupportedDocumentsFilter();
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc, erManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allSupportedDocumentsFilter("wrong.name");
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc, erManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allSupportedDocumentsFilter(erDoc.getName(), erManifestDoc.getName());
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, manifestDoc, archiveManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter.setTimestampDocuments(false);
        asicContentDocumentFilter.setArchiveManifestDocuments(false);
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, manifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allDocumentsFilter();
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc, erManifestDoc, mimetype, unsupportedDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allDocumentsFilter("wrong.name");
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc, erManifestDoc, mimetype, unsupportedDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter = ASiCContentDocumentFilterFactory.allDocumentsFilter("wrong.name", unsupportedDoc.getName(), mimetype.getName());
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc, erManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));

        asicContentDocumentFilter.setEvidenceRecordManifestDocuments(false);
        assertEquals(new HashSet<>(Arrays.asList(signedDoc, signatureDoc, timestampDoc, erDoc, manifestDoc, archiveManifestDoc)),
                new HashSet<>(asicContentDocumentFilter.filter(asicContent)));
    }

}

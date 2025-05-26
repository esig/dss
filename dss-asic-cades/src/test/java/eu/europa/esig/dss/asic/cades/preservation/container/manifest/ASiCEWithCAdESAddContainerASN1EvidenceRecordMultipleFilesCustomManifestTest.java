package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.List;

class ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesCustomManifestTest extends ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Arrays.asList(
                new InMemoryDocument("Test 12345".getBytes(), "text1"),
                new InMemoryDocument("Test 67890".getBytes(), "text2")
        );
    }

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
    }

}

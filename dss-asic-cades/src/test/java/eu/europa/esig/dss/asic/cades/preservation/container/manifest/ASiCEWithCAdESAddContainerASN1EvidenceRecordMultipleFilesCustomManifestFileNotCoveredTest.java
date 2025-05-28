package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesCustomManifestFileNotCoveredTest extends ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest {

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
        asicContent.setSignedDocuments(Collections.singletonList(
                new InMemoryDocument("Test 12345".getBytes(), "text1")
        ));
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The original document with name 'text2' is not covered by the evidence record!", exception.getMessage());
    }

}

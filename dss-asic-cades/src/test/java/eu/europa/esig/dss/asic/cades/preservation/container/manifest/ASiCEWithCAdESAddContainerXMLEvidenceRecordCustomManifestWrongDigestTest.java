package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerXMLEvidenceRecordTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithCAdESAddContainerXMLEvidenceRecordCustomManifestWrongDigestTest extends ASiCEWithCAdESAddContainerXMLEvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(Collections.singletonList(new InMemoryDocument("Hello world!".getBytes(), "test.txt")));
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The manifest entry 'test.txt' was not found or digest does not intact! " +
                "Please provide a valid ASiCEvidenceRecordManifest document.", exception.getMessage());
    }

}

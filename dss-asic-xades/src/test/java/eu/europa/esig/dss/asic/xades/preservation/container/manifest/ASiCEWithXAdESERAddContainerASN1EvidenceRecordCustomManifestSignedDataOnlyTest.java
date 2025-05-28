package eu.europa.esig.dss.asic.xades.preservation.container.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.preservation.container.ASiCEWithXAdESERAddContainerASN1EvidenceRecordTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithXAdESERAddContainerASN1EvidenceRecordCustomManifestSignedDataOnlyTest extends ASiCEWithXAdESERAddContainerASN1EvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        DSSDocument originalASiCContainer = getDocumentsToPreserve().get(0);
        ASiCContent asicContent = new ASiCWithXAdESContainerExtractor(originalASiCContainer).extract();
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter())
                .build();
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest of document 'META-INF/signatures.xml' has not been found " +
                "within the manifest file or/and evidence record!", exception.getMessage());
    }

}

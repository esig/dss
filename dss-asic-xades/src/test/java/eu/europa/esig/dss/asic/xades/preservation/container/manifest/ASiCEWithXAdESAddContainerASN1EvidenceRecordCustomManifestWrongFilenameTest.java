package eu.europa.esig.dss.asic.xades.preservation.container.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.preservation.container.ASiCEWithXAdESAddContainerASN1EvidenceRecordTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithXAdESAddContainerASN1EvidenceRecordCustomManifestWrongFilenameTest extends ASiCEWithXAdESAddContainerASN1EvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        DSSDocument manifestDocument = new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
        manifestDocument.setName("META-INF/ASiCEvidenceRecordWrongFilenameManifestAAA.xml");
        return manifestDocument;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("The manifest filename 'META-INF/ASiCEvidenceRecordWrongFilenameManifestAAA.xml' " +
                "is not compliant to the ASiCEvidenceRecordManifest filename convention!", exception.getMessage());
    }

}

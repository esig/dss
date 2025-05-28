package eu.europa.esig.dss.asic.xades.preservation.container.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.preservation.container.ASiCEWithXAdESAddContainerASN1EvidenceRecordTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

class ASiCEWithXAdESAddContainerASN1EvidenceRecordCustomManifestTest extends ASiCEWithXAdESAddContainerASN1EvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        DSSDocument manifestDocument = new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
        manifestDocument.setName("META-INF/ASiCEvidenceRecordManifestAAA.xml");
        return manifestDocument;
    }

}

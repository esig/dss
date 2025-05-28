package eu.europa.esig.dss.asic.xades.preservation.container.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.preservation.container.ASiCSWithXAdESAddContainerXMLEvidenceRecordTest;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithXAdESAddContainerXMLEvidenceRecordCustomManifestTest extends ASiCSWithXAdESAddContainerXMLEvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        DSSDocument manifestDocument = new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.xml")
                .build();
        manifestDocument.setName("META-INF/ASiCEvidenceRecordManifestAAA.xml");
        return manifestDocument;
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        // Manifest is ignored for ASiC-S
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getContainerInfo().getManifestFiles()));
    }

}

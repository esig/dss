package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerXMLEvidenceRecordTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCEWithCAdESAddContainerXMLEvidenceRecordCustomManifestTest extends ASiCEWithCAdESAddContainerXMLEvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        DSSDocument manifestDocument = new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecordAAA.xml")
                .build();
        manifestDocument.setName("META-INF/ASiCEvidenceRecordManifestAAA.xml");
        return manifestDocument;
    }

    @Override
    protected void checkEvidenceRecordFilename(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordFilename(diagnosticData);

        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals("META-INF/evidencerecordAAA.xml", evidenceRecordWrapper.getFilename());
    }

}

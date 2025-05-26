package eu.europa.esig.dss.asic.xades.preservation.container.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.preservation.container.ASiCEWithXAdESERAddContainerASN1EvidenceRecordTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

class ASiCEWithXAdESERAddContainerASN1EvidenceRecordCustomManifestTest extends ASiCEWithXAdESERAddContainerASN1EvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        DSSDocument originalASiCContainer = getDocumentsToPreserve().get(0);
        ASiCContent asicContent = new ASiCWithXAdESContainerExtractor(originalASiCContainer).extract();
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.archiveDocumentsFilter()) // default
                .build();
    }

}

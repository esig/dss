package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerXMLEvidenceRecordTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithCAdESAddContainerXMLEvidenceRecordCustomManifestWrongERFilenameTest extends ASiCEWithCAdESAddContainerXMLEvidenceRecordTest {

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
       ASiCContent asicContent = new ASiCContent();
       asicContent.setSignedDocuments(getDocumentsToPreserve());
       DSSDocument manifestDocument = new ASiCEvidenceRecordManifestBuilder(
          asicContent, DigestAlgorithm.SHA256, "META-INF/evidence001record001.xml")
          .build();
       manifestDocument.setName("META-INF/ASiCEvidenceRecordManifestAAA.xml");
       return manifestDocument;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("RFC 6283 XML Evidence Record's filename 'META-INF/evidence001record001.xml' is " +
              "not compliant to the ASiC with CAdES filename convention!", exception.getMessage());
    }

}

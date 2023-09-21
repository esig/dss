package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESLevelLTWithTwoEvidenceRecordsValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-two-ers-multi-files.sce");
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertEquals(2, signatureEvidenceRecords.size());

            boolean firstErFound = false;
            boolean secondErFound = false;

            for (XmlEvidenceRecord xmlEvidenceRecord : signatureEvidenceRecords) {
                assertNotNull(xmlEvidenceRecord.getPOETime());
                assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
                if (Utils.collectionSize(evidenceRecordScopes) == 4) {
                    firstErFound = true;
                } else if (Utils.collectionSize(evidenceRecordScopes) == 6) {
                    secondErFound = true;
                }

                boolean sigFileFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);

                XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
                assertNotNull(timestamps);
                assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

                for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                    assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                    List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                    assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));

                    sigFileFound = false;
                    for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (simpleReport.getTokenFilename(sigId).equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);
                }
            }
            assertTrue(firstErFound);
            assertTrue(secondErFound);
        }
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 0; // not used
    }

}

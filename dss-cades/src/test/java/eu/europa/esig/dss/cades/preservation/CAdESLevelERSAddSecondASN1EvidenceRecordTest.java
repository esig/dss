package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelERSAddSecondASN1EvidenceRecordTest extends AbstractCAdESAddEvidenceRecordTest {

    private boolean parallelER = false;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CAdESLevelBDetachedAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS.p7m"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CAdESLevelBDetachedAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-C-E-ERS.ers"));
    }

    @Override
    protected CAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        CAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setParallelEvidenceRecord(parallelER);
        return parameters;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());
        assertNotEquals(evidenceRecords.get(0).getId(), evidenceRecords.get(1).getId());
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestampedReferences(diagnosticData);

        int ersDoNotCoverERs = 0;
        int ersCoverERs = 0;
        for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
            List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
            assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));

            if (Utils.isCollectionEmpty(evidenceRecord.getCoveredEvidenceRecords())) {
                ++ersDoNotCoverERs;
            } else {
                ++ersCoverERs;
            }
        }
        assertEquals(1, ersDoNotCoverERs);
        assertEquals(1, ersCoverERs);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        String tstId = null;
        for (EvidenceRecordWrapper evidenceRecordWrapper : evidenceRecords) {
            List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
            assertEquals(1, timestampList.size());

            TimestampWrapper timestampWrapper = timestampList.get(0);
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());

            if (tstId == null) {
                tstId = timestampWrapper.getId();
            } else {
                assertNotEquals(tstId, timestampWrapper.getId());
            }
        }
    }

    @Override
    protected DSSDocument getSignedDocument() {
        CAdESService service = getService();

        parallelER = false;

        DSSDocument twoERDoc = service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());

        parallelER = true;

        Exception exception = assertThrows(IllegalInputException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("The digest covered by the evidence record do not correspond to the digest computed on the signature!", exception.getMessage());

        return twoERDoc;
    }

}

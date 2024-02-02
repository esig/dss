package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithTstWithAsn1EvidenceRecordValidationTest extends AbstractASiCWithCAdESTestValidation {
    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/tst-with-asn1-er.sce");
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(0, Utils.collectionSize(diagnosticData.getSignatures()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> nonEvidenceRecordTimestamps = diagnosticData.getNonEvidenceRecordTimestamps();
        assertEquals(1, nonEvidenceRecordTimestamps.size());

        TimestampWrapper timestampWrapper = nonEvidenceRecordTimestamps.get(0);
        List<EvidenceRecordWrapper> evidenceRecords = timestampWrapper.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(1, evidenceRecordWrapper.getCoveredTimestamps().size());
        assertEquals(2, evidenceRecordWrapper.getCoveredSignedData().size());
        assertEquals(2, evidenceRecordWrapper.getCoveredCertificates().size());

        List<TimestampWrapper> erTimestamps = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, erTimestamps.size());
        assertNotEquals(timestampWrapper.getId(), erTimestamps.get(0).getId());
        for (TimestampWrapper timestamp : erTimestamps) {
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isSignatureValid());
        }
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        // skip
    }

}

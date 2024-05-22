package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordOnTimestampValidationTest extends AbstractDocumentTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/d-trust.tsr");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("Test123".getBytes()));
    }

    @Override
    protected List<DSSDocument> getDetachedEvidenceRecords() {
        return Collections.singletonList(new FileDocument("src/test/resources/er-asn1-on-tst.ers"));
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
        assertEquals(3, evidenceRecordWrapper.getCoveredCertificates().size());

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
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        // skip
    }

}

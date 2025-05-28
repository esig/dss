package eu.europa.esig.dss.asic.xades.preservation.container;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithXAdESAddContainerXMLEvidenceRecordInvalidTstTest extends AbstractASiCWithXAdESTestAddContainerEvidenceRecord {

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    public void init() {
        certificateVerifier = super.getOfflineCertificateVerifier();
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        return certificateVerifier;
    }

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/signable/test.txt"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-test-txt-invalid-tst.xml");
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1;
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(1, timestamps.size());

        TimestampToken timestampToken = timestamps.get(0);
        assertTrue(timestampToken.isMessageImprintDataFound());
        assertFalse(timestampToken.isMessageImprintDataIntact());
        assertFalse(timestampToken.isValid());
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            assertTrue(Utils.isCollectionNotEmpty(timestamps));
            for (TimestampWrapper timestampWrapper : timestamps) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertFalse(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());
            }
        }
    }

    @Test
    @Override
    public void addERAndValidate() {
        certificateVerifier.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());

        Exception exception = assertThrows(AlertException.class, super::addERAndValidate);
        assertTrue(exception.getMessage().contains("Broken timestamp(s) detected."));

        certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert());

        super.addERAndValidate();
    }

}

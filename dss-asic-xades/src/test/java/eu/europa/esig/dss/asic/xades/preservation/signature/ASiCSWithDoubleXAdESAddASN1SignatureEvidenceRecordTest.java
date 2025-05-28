package eu.europa.esig.dss.asic.xades.preservation.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithDoubleXAdESAddASN1SignatureEvidenceRecordTest extends AbstractASiCWithXAdESAddSignatureEvidenceRecordTest {

    private String signatureId = null;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/multifiles-ok.asics");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-multifiles-s-ok.ers");
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        int sigWithErCounter = 0;
        int sigWithoutErCounter = 0;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
                checkEvidenceRecordCoverage(diagnosticData, signature);
                ++sigWithErCounter;
            } else {
                ++sigWithoutErCounter;
            }
        }
        assertEquals(1, sigWithErCounter);
        assertEquals(1, sigWithoutErCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.XAdES_BASELINE_B, signature.getSignatureFormat());
        }
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfCoveredDocuments() {
        return 3;
    }

    @Override
    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        XAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setSignatureId(signatureId);
        return parameters;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("More than one signature found in a document! " +
                "Please provide a signatureId within the parameters.", exception.getMessage());

        signatureId = "not-existing";
        exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("A signature with id 'not-existing' has not been found!", exception.getMessage());

        // wrong signature
        signatureId = "id-eef6990e2d0a7d354d7b3cadec31402a";
        exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to the digest computed " +
                        "on the signature and/or detached content!",
                exception.getMessage());

        // wrong signature
        signatureId = "id-ab45cb0f04c9f70f278a9a5f355775ad";
        super.addERAndValidate();
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            assertTrue(Utils.isCollectionNotEmpty(timestamps));
            for (TimestampWrapper timestampWrapper : timestamps) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
            }
        }
    }

}

package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DoubleCAdESLevelLTAddASN1EvidenceRecordTest extends AbstractCAdESAddEvidenceRecordTest {

    private String signatureId = null;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CAdESLevelLTAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/Double-C-B-B-basic.p7m"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CAdESLevelLTAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-Double-C-B-B-basic.ers"));
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        int sigWithErCounter = 0;
        int sigWithoutErCounter = 0;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
                assertEquals(1, Utils.collectionSize(signature.getEvidenceRecords()));
                assertEquals(signatureId, signature.getEvidenceRecords().get(0).getParent().getId());
                checkEvidenceRecordCoverage(diagnosticData, signature);
                ++sigWithErCounter;
            } else {
                ++sigWithoutErCounter;
            }
        }
        assertEquals(2, sigWithErCounter);
        assertEquals(0, sigWithoutErCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.CAdES_BASELINE_B, signature.getSignatureFormat());
        }
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 3; // two signatures + doc
    }

    @Override
    protected CAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        CAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setSignatureId(signatureId);
        return parameters;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals(String.format("More than one signature found in a document with name '%s'! " +
                "Please provide a signatureId within the parameters.", getSignatureDocument().getName()), exception.getMessage());

        signatureId = "not-existing";
        exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("Unable to find a signature with Id : not-existing!", exception.getMessage());

        // first signature
        signatureId = "S-429C1BC7D41D6D1D107A10502400D4F2F47DA1D6C07FF8026C65B2D82B73BBFF";
        super.addERAndValidate();

        // second signature
        signatureId = "S-0F5EAFA56142DB2BBF7746C389AC4C9D2CDD9C32CEB28F86FB13A504F9EB7B6F";
        super.addERAndValidate();
    }

}

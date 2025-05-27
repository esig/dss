package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DoubleCAdESLevelLTAddASN1EvidenceRecordTest extends AbstractCAdESAddEvidenceRecordTest {

    private String signatureId = null;

    private int expectedEvidenceRecords = 1;

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
                assertEquals(expectedEvidenceRecords, Utils.collectionSize(signature.getEvidenceRecords()));
                for (EvidenceRecordWrapper evidenceRecordWrapper : signature.getEvidenceRecords()) {
                    assertEquals(signatureId, evidenceRecordWrapper.getParent().getId());
                }
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
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        super.checkEvidenceRecordCoverage(diagnosticData, signature);

        if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
            int erCoveringERCounter = 0;
            int erNotCoveringERCounter = 0;
            for (EvidenceRecordWrapper evidenceRecordWrapper : signature.getEvidenceRecords()) {
                if (Utils.isCollectionNotEmpty(evidenceRecordWrapper.getCoveredEvidenceRecords())) {
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecordWrapper.getCoveredTimestamps()));
                    ++erCoveringERCounter;
                } else {
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecordWrapper.getCoveredTimestamps()));
                    ++erNotCoveringERCounter;
                }
            }
            assertEquals(expectedEvidenceRecords - 1, erCoveringERCounter);
            assertEquals(1, erNotCoveringERCounter);
        }
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
        CAdESService service = getService();

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals(String.format("More than one signature found in a document with name '%s'! " +
                "Please provide a signatureId within the parameters.", getSignatureDocument().getName()), exception.getMessage());

        signatureId = "not-existing";
        exception = assertThrows(IllegalArgumentException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("Unable to find a signature with Id : not-existing!", exception.getMessage());

        SignedDocumentValidator validator = getValidator(getSignatureDocument());
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        // first signature
        signatureId = signatures.get(0).getId();
        DSSDocument signatureDocWithER = service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());
        verify(signatureDocWithER);

        // second signature
        signatureId = signatures.get(1).getId();
        DSSDocument signatureTwoWithER = service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());
        verify(signatureTwoWithER);

        expectedEvidenceRecords = 2;

        DSSDocument secondER = new InMemoryDocument(CAdESLevelLTAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-second-Double-C-B-B-basic.ers"));

        // first signature
        signatureId = signatures.get(0).getId();

        exception = assertThrows(IllegalInputException.class, () ->
                service.addSignatureEvidenceRecord(signatureTwoWithER, secondER, getEvidenceRecordIncorporationParameters()));
        assertEquals("At most one of the SignerInfo instances within the SignedData instance shall contain " +
                "evidence-records attributes! Please abolish the operation or provide another signature Id.", exception.getMessage());

        // second signature
        signatureId = signatures.get(1).getId();

        DSSDocument signaturesDocWithTwoER = service.addSignatureEvidenceRecord(signatureTwoWithER, secondER, getEvidenceRecordIncorporationParameters());
        verify(signaturesDocWithTwoER);
    }

}
